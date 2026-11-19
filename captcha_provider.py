import asyncio
import logging
import re
from typing import Optional

import httpx
from playwright.async_api import Page

logger = logging.getLogger("captcha_provider")

TWO_CAPTCHA_IN_URL = "https://2captcha.com/in.php"
TWO_CAPTCHA_RES_URL = "https://2captcha.com/res.php"


class CaptchaNotConfiguredError(RuntimeError):
    """Выбрасывается, когда ключ капчи не настроен."""


class CaptchaSolvingError(RuntimeError):
    """Выбрасывается при ошибке сервиса решения капчи (баланс, таймаут, неверный ключ)."""


async def extract_recaptcha_sitekey(page: Page) -> Optional[str]:
    """
    Извлекает sitekey reCAPTCHA со страницы.
    Проверяет:
      1. Атрибуты data-sitekey на элементах контейнера капчи.
      2. iframe URL (параметр k=...).
      3. Глобальные скрипты.
    """
    # 1. Поиск в атрибутах контейнера (например, .g-recaptcha, [data-sitekey])
    locator = page.locator("[data-sitekey]").first
    if await locator.count() > 0:
        key = await locator.get_attribute("data-sitekey")
        if key and key.strip():
            return key.strip()

    # 2. Поиск в iframe src (reCAPTCHA v2 iframe)
    frames = page.frames
    for frame in frames:
        frame_url = frame.url or ""
        if "recaptcha" in frame_url:
            match = re.search(r"[?&]k=([A-Za-z0-9_-]+)", frame_url)
            if match:
                return match.group(1)

    # 3. Поиск по всему HTML страницы
    try:
        content = await page.content()
        match = re.search(r'data-sitekey=["\']([A-Za-z0-9_-]{20,50})["\']', content)
        if match:
            return match.group(1)
    except Exception:
        pass

    return None


async def request_2captcha_solution(
    *,
    api_key: str,
    sitekey: str,
    page_url: str,
    timeout_seconds: int = 120,
    poll_interval: float = 5.0,
    client: Optional[httpx.AsyncClient] = None,
) -> str:
    """
    Отправляет задачу на решение reCAPTCHA в сервис 2captcha и ожидает токен ответа.
    """
    should_close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=15.0)
        should_close_client = True

    try:
        # Шаг 1: отправка задачи
        in_params = {
            "key": api_key,
            "method": "userrecaptcha",
            "googlekey": sitekey,
            "pageurl": page_url,
            "json": 1,
        }

        resp = await client.post(TWO_CAPTCHA_IN_URL, data=in_params)
        data = resp.json()

        if data.get("status") != 1:
            error_code = data.get("request", "UNKNOWN_ERROR")
            raise CaptchaSolvingError(f"2captcha ошибка создания задачи: {error_code}")

        task_id = data.get("request")
        if not task_id:
            raise CaptchaSolvingError("2captcha не вернул ID задачи")

        # Шаг 2: опрос результата
        start_time = asyncio.get_event_loop().time()
        while True:
            await asyncio.sleep(poll_interval)

            if asyncio.get_event_loop().time() - start_time > timeout_seconds:
                raise CaptchaSolvingError(
                    f"Превышено время ожидания решения капчи ({timeout_seconds} сек)"
                )

            res_params = {
                "key": api_key,
                "action": "get",
                "id": task_id,
                "json": 1,
            }
            res_resp = await client.get(TWO_CAPTCHA_RES_URL, params=res_params)
            res_data = res_resp.json()

            if res_data.get("status") == 1:
                token = res_data.get("request")
                if token:
                    return token
                raise CaptchaSolvingError("2captcha вернул пустой токен")

            request_state = res_data.get("request", "")
            if request_state == "CAPCHA_NOT_READY":
                continue

            raise CaptchaSolvingError(f"2captcha ошибка решения: {request_state}")

    finally:
        if should_close_client:
            await client.aclose()


async def inject_captcha_token(page: Page, token: str) -> None:
    """
    Подставляет полученный токен в DOM страницы и вызывает callback reCAPTCHA.
    """
    js_code = """(token) => {
        // Подставляем токен во все поля ответа g-recaptcha-response
        const inputs = document.querySelectorAll('[name="g-recaptcha-response"], #g-recaptcha-response');
        inputs.forEach(el => {
            el.value = token;
            el.innerHTML = token;
            el.style.display = 'block';
        });

        // Проверяем наличие зарегистрированных коллбеков в объекте ___grecaptcha_cfg
        try {
            if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
                for (const clientId in window.___grecaptcha_cfg.clients) {
                    const client = window.___grecaptcha_cfg.clients[clientId];
                    for (const prop in client) {
                        if (client[prop] && typeof client[prop].callback === 'function') {
                            client[prop].callback(token);
                            return true;
                        }
                        if (client[prop] && typeof client[prop].promise === 'object') {
                            // обработка вариаций
                        }
                    }
                }
            }
        } catch (e) {
            console.warn("Ошибка вызова callback reCAPTCHA:", e);
        }
        return true;
    }"""
    await page.evaluate(js_code, token)


async def handle_captcha_step(page: Page, page_url: str, api_key: str) -> None:
    """
    Автоматический шаг решения капчи перед сабмитом формы.
    Если на странице нет капчи, шаг пропускается без ошибок.
    """
    sitekey = await extract_recaptcha_sitekey(page)
    if not sitekey:
        logger.info("Капча на странице не обнаружена или не требует решения.")
        return

    cleaned_key = (api_key or "").strip()
    if not cleaned_key:
        raise CaptchaNotConfiguredError(
            "На форме обнаружена reCAPTCHA, но CAPTCHA_API_KEY не задан в конфигурации (.env)"
        )

    token = await request_2captcha_solution(
        api_key=cleaned_key,
        sitekey=sitekey,
        page_url=page_url,
    )

    await inject_captcha_token(page, token)
    await page.wait_for_timeout(500)
