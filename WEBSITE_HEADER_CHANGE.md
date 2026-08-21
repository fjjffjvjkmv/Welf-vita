# تغییر برچسب Support به Website

در پاسخ Subscription، هدر `support-url` حذف شده و به‌جای آن هدر استاندارد زیر ارسال می‌شود:

```text
profile-web-page-url: https://YOUR_DOMAIN/sub/UUID
```

کلاینت‌های سازگار این هدر را به‌عنوان **Website** یا **Open web page** نمایش می‌دهند. URL مقصد همان صفحهٔ Subscription کاربر است و تغییری در feed، لینک raw یا اطلاعات اتصال ایجاد نمی‌شود.

دلیل حذف کامل `support-url` این است که وجود آن باعث می‌شود کلاینت‌های سازگار همان URL را با برچسب ثابت **Support** نمایش دهند. مدل دادهٔ صفحهٔ عمومی همچنین کلید `subWebsiteUrl` را در کنار کلید سازگار قدیمی `subSupportUrl` ارائه می‌کند.
