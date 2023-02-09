from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):

    def create_user(self, email, first_name, last_name, password=None, password2=None):
        """
        Creates and saves a User with the given email, first_name, last_name and password.
        """
        if not email:
            raise ValueError('User must have an email address')

        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, password=None):
        """
        Creates and saves a superuser with the given email, first_name, last_name and password.
        """
        user = self.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractUser):
    # email = models.EmailField(
    #     verbose_name='Email',
    #     max_length=255,
    #     unique=False,
    # )
    email = models.EmailField(max_length=255, unique=True)
    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)
    username = models.CharField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, null=True, blank=True)

    refresh_token = models.TextField(null=True, blank=True)
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_superuser

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_superuser


class Blog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    blog_title = models.CharField(max_length=255)
    blog_image = models.ImageField(upload_to='sample_blog_images', height_field=None, width_field=None, max_length=100, null=True, blank=True)
    blog_content = models.TextField(null=True, blank=True)
    publish_choices = (
        ('Yes', 'Published'),
        ('No', 'Draft'),
    )
    is_published = models.CharField(max_length=255, blank=True, choices=publish_choices)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)