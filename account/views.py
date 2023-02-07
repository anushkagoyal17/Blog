import logging
from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from account.renderers import UserRenderer
from .models import User
from rest_framework.response import Response
from .serializers import UserSerializer, CustomTokenObtainPairSerializer
from rest_framework import status
from django.contrib.auth import authenticate
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


logger = logging.getLogger('django')

class UserRegistrationView(GenericAPIView):
    renderer_classes = (UserRenderer,)

    serializer_class = UserSerializer

    def post(self, request, format=None):
        '''
        This method is used to register the user.
        '''
        try:
            import pdb; pdb.set_trace()
            email = request.data.get('email').lower()
            if email in User.objects.values_list('email', flat=True):
                return Response({'msg': 'An account with the given email already exists'}, status=status.HTTP_403_FORBIDDEN)
            username = request.data.get('username').lower()
            if username in User.objects.values_list('username', flat=True):
                return Response({'msg': 'Username already exists'}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                # uid = user.id
                uid = urlsafe_base64_encode(force_bytes(user.id))
                # verify_email(request, user, uid)
            return Response({'uid': uid, 'email': email,
                             'msg': 'Registration Successful, Email verification link sent. Please verify your email.'},
                            status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(e)
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLoginView(GenericAPIView):
    renderer_classes = (UserRenderer,)

    def post(self, request, format=None):
        '''
        This method is used to login.
        '''
        email = request.data.get('email').lower()
        password = request.data.get('password')
        user = authenticate(email=email, password=password)

        if user and user.is_verified is False:
            return Response({'errors': {'non_field_errors': ['Please Verify your Email to login']}},
                            status=status.HTTP_404_NOT_FOUND)

        if user and user.is_active:
            token = CustomTokenObtainPairSerializer.get_token(user)
            return Response({'token': token, 'msg': 'Login Success'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'errors': {'non_field_errors': ['Email or Password is not Valid']}},
                            status=status.HTTP_404_NOT_FOUND)


