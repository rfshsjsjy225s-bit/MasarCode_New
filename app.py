import os
import re
import logging
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp
from dotenv import load_dotenv
import bleach
from datetime import datetime

# تحميل المتغيرات البيئية
load_dotenv()

# تهيئة التطبيق
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['SESSION_COOKIE_SECURE'] = True          # إرسال cookies فقط عبر HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True        # منع الوصول للكوكيز عبر JS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'       # حماية CSRF
app.config['WTF_CSRF_ENABLED'] = False
app.config['WTF_CSRF_TIME_LIMIT'] = 3600            # صلاحية رمز CSRF (معطلة في Serverless)

# إعداد نظام التسجيل (Logging) — محمي ضد أخطاء الكتابة في بيئة Serverless
try:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/security.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('MasarCode Agency Started')
except Exception:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    stream_handler.setLevel(logging.INFO)
    app.logger.addHandler(stream_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('MasarCode Agency啟動 (stream)')

# قائمة العناوين المسموح بها للأمان (منع Open Redirect)
ALLOWED_REDIRECTS = {'/', '/contact', '/portfolio', '/services'}

# ------------------ نموذج الاتصال الآمن ------------------
class ContactForm(FlaskForm):
    name = StringField('الاسم', validators=[
        DataRequired(message='الاسم مطلوب'),
        Length(min=2, max=50, message='الاسم يجب أن يكون بين 2 و50 حرفاً'),
        Regexp(r'^[\u0600-\u06FF\sA-Za-z]+$', message='يُسمح فقط بالحروف العربية والإنجليزية والمسافات')
    ])
    email = EmailField('البريد الإلكتروني', validators=[
        DataRequired(message='البريد الإلكتروني مطلوب'),
        Email(message='أدخل بريداً إلكترونياً صالحاً'),
        Length(max=100)
    ])
    message = TextAreaField('الرسالة', validators=[
        DataRequired(message='الرسالة مطلوبة'),
        Length(min=10, max=2000, message='الرسالة يجب أن تكون بين 10 و2000 حرف')
    ])
    submit = SubmitField('إرسال')

    # تنظيف إضافي مخصص
    def sanitize_input(self):
        # استخدام bleach لتنظيف النصوص ومنع XSS
        self.name.data = bleach.clean(self.name.data, strip=True)
        self.email.data = bleach.clean(self.email.data, strip=True)
        # السماح ببعض علامات HTML الآمنة للرسالة؟ لا نسمح بأي علامات
        self.message.data = bleach.clean(self.message.data, strip=True, tags=[], attributes={}, protocols=[])

# ------------------ مساعدات الأمان ------------------
def sanitize_string(input_str):
    """تنظيف أي مدخل نصي عام"""
    if input_str is None:
        return ''
    allowed_tags = []  # نمنع أي HTML تماماً
    return bleach.clean(input_str, strip=True, tags=allowed_tags, attributes={}, protocols=[])

def is_safe_redirect(target):
    """منع إعادة التوجيه المفتوحة"""
    if not target:
        return False
    # استخراج المسار إذا كان الرابط داخلياً
    if target.startswith('/') and not target.startswith('//'):
        return target in ALLOWED_REDIRECTS or target == url_for('index')
    return False

# ------------------ إضافة رؤوس أمان HTTP ------------------
@app.after_request
def set_security_headers(response):
    # منع تخمين نوع MIME
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # سياسة الأمان الصارمة (CSP) – مثال مبسط، يسمح بتحميل Tailwind وFont Awesome من CDN
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://kit.fontawesome.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://via.placeholder.com; "
        "connect-src 'self'"
    )
    # حماية من هجمات Clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # تمكين HSTS (لـ HTTPS فقط في الإنتاج)
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ------------------ الصفحات ------------------
@app.route('/')
def index():
    form = ContactForm()
    return render_template('index.html', form=form)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        # تنظير البيانات بشكل صارم
        form.sanitize_input()
        name = form.name.data
        email = form.email.data
        message = form.message.data

        # محاكاة إرسال البريد (في الإنتاج نستخدم Flask-Mail مع TLS)
        app.logger.info(f'رسالة جديدة من {name} <{email}>: {message[:50]}...')
        flash('تم إرسال رسالتك بنجاح. سنتواصل معك قريباً!', 'success')
        return redirect(url_for('index'))
    return render_template('index.html', form=form, active_contact_form=True)

# صفحة بسيطة لتأكيد إرسال النموذج (تم دمجه مع الفلاش)

# معالجة الأخطاء
@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f'404 خطأ: {request.path}')
    form = ContactForm()
    return render_template('index.html', form=form, error_404=True), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f'500 خطأ: {str(e)}')
    form = ContactForm()
    return render_template('index.html', form=form, error_500=True), 500

# منع الوصول المباشر للملفات الحساسة
@app.route('/.env')
@app.route('/config.py')
def forbidden_config():
    app.logger.warning(f'محاولة وصول غير مصرح بها لملف التكوين من {request.remote_addr}')
    return make_response("Forbidden", 403)

# لا تشغّل الخادم محلياً هنا - Vercel يتوقع وجود متغير `app` فقط

# Alias expected by some WSGI adapters / serverless runtimes
# Ensure a top-level `handler` name points to the Flask app
handler = app
app = app