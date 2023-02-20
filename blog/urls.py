from django.contrib import admin
from django.urls import path, include
from account.views import ResetPassword


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/user/', include('account.urls')),
    path('reset-password/<token>', ResetPassword.as_view(), name='reset-password'),

    # path('verify-email/<uid>/<email_token>', UserEmailVerificationView.as_view(), name='verify-email'),
]