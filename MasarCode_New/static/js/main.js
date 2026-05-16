// منع المحاولات الخبيثة على العميل بشكل إضافي
document.addEventListener('DOMContentLoaded', function() {
    // تحقق من جميع النماذج قبل الإرسال
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            let dangerous = false;
            const inputs = form.querySelectorAll('input, textarea');
            inputs.forEach(input => {
                if (input.value && /<[^>]*script/i.test(input.value)) {
                    dangerous = true;
                    input.value = input.value.replace(/<[^>]*>/g, '');
                }
            });
            if (dangerous) {
                alert('تم اكتشاف محتوى غير آمن وتم تنقيته تلقائياً.');
            }
        });
    });

    // إخفاء رسائل الفلاش بعد 5 ثوانٍ
    const flashMsg = document.querySelector('.bg-green-900\\/50');
    if (flashMsg) {
        setTimeout(() => { flashMsg.style.display = 'none'; }, 5000);
    }
});