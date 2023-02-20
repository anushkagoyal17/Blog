import re, logging
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User, Blog
from rest_framework import serializers
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str


logger = logging.getLogger('django')

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['first_name'] = user.first_name
        token['last_name'] = user.last_name
        token['email'] = user.email
        token['is_superuser'] = user.is_superuser
        user.refresh_token = str(token)
        user.save()
        
        return {
            'refresh': str(token),
            'access': str(token.access_token),
        }


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'username', 'password', 'is_verified',)
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


    def validate(self, attrs):
        min_length=8
        max_length=25
        
        password = attrs.get('password')
        
        if len(password) < min_length or len(password) > max_length:
            raise serializers.ValidationError("Password length must be 8-25 characters")
        if not re.findall('[A-Z]', password):
            raise serializers.ValidationError(
                ("The password must contain at least one uppercase letter, A-Z."),
                code='password_no_upper',
            )
        if not re.findall('[a-z]', password):
            raise serializers.ValidationError(
                ("The password must contain at least one lowercase letter, a-z."),
                code='password_no_lower',
            )
        if not re.findall('[0-9]', password):
            raise serializers.ValidationError(
                ("The password must contain at least one number, 0-9."),
                code='password_no_num',
            )
        if not re.findall('[^\w\*]', password):
            raise serializers.ValidationError(
                ('The password must contain at least one special character, /[*@!#%&()^~}{]+/'),
                code='password_no_symbol',
            )
        return attrs


class VerifyAccountSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()


class BlogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = '__all__'
        read_only_fields = ['user']


class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    class Meta:
        # model = User
        fields = ['email',]

    # def validate(self, attrs):
    #     try:
    #         email = attrs.get('email','')
    #         if User.objects.filter(email=email).exists():
    #             user = User.objects.get(email=email)
    #             uid = urlsafe_base64_encode(user.id)
    #             token = PasswordResetTokenGenerator().make_token(user)
    #     except:
    #         pass
    def create(self, validated_data):
        return User.objects.update(**validated_data)

class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True)
    password2 = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        import pdb; pdb.set_trace()
        uid = self.context.get('uid')
        token = self.context.get('token')
        # context = {
        #         'token': token,
        #         }
        id = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError('Token is not Valid or Expired')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs
        
    def create(self, validated_data):
        return User.objects.update(**validated_data)
