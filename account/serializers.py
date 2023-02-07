import re, logging
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User
from rest_framework import serializers

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
        fields = ['id', 'email', 'first_name', 'last_name', 'username', 'password']
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

