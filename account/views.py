import logging, datetime
from django.shortcuts import render
from rest_framework.generics import GenericAPIView, ListCreateAPIView
from account.renderers import UserRenderer
from .models import User, Blog
from rest_framework.response import Response
from .serializers import UserSerializer, CustomTokenObtainPairSerializer, \
VerifyAccountSerializer, BlogSerializer
from rest_framework import status, serializers
from django.contrib.auth import authenticate
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .emails import send_otp_via_mail
from rest_framework.permissions import IsAuthenticated


logger = logging.getLogger('django')

class UserRegistrationView(GenericAPIView):
    renderer_classes = (UserRenderer,)

    serializer_class = UserSerializer

    def post(self, request, format=None):
        '''
        This method is used to register the user.
        '''
        try:
            email = request.data.get('email').lower()
            if email in User.objects.values_list('email', flat=True):
                return Response({'msg': 'An account with the given email already exists'}, status=status.HTTP_403_FORBIDDEN)
            username = request.data.get('username').lower()
            if username in User.objects.values_list('username', flat=True):
                return Response({'msg': 'Username already exists'}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            send_otp_via_mail(serializer.data['email'])
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                # uid = user.id
                uid = urlsafe_base64_encode(force_bytes(user.id))
                # verify_email(request, user, uid)
            return Response({'uid': uid, 'email': email,
                             'msg': 'Please verify OTP sent to your email.'},
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


class VerifyOTP(GenericAPIView):
    def post(self, request):
        try:
            data = request.data
            serializer = VerifyAccountSerializer(data = data)
            if serializer.is_valid():
                email = serializer.data['email']
                otp = serializer.data['otp']

                user = User.objects.get(email=email)
                if not user:
                    return Response({
                            'status' : 400,
                            'message' : 'Failed',
                            'data' : 'Invalid Email',
                        }) 

                if not user.otp == otp:
                    return Response({
                            'status' : 400,
                            'message' : 'Failed',
                            'data' : 'Wrong OTP',
                        }) 
                user.is_verified = True
                user.save()

                return Response({
                    'status' : 200,
                    'message' : 'Verification Successful',
                    'data' : serializer.data,
                })

                
        except Exception as e:
            return Response({
                    'status' : 400,
                    'message' : 'Failed',
                    'data' : serializer.errors,
                })  


class CreateNewBlog(GenericAPIView):
    renderer_classes = (UserRenderer,)
    permission_classes = (IsAuthenticated,)
    serializer_class = BlogSerializer

    def get(self, request, format=None):
        try:
            blogs = Blog.objects.filter(user=request.user)
            serializer = self.serializer_class(blogs, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(e)
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, format=None):
        try:
            data = request.data
            title_list = Blog.objects.filter(user=request.user).values_list('blog_title', flat=True)
            blog_title = request.data.get('blog_title')
            if blog_title:
                if blog_title in title_list:
                    return Response({"Error": "You've already a blog with this title!"}, status=status.HTTP_404_NOT_FOUND)
                blog_image = request.data.get('blog_image')
                blog_content = request.data.get('blog_content')
                is_published = request.data.get('is_published')
                
                context = {
                    'blog_title': blog_title,
                    'blog_image': blog_image,
                    'blog_content': blog_content,
                    'is_published': is_published,
                    # 'username': username,
                }
                if is_published == 'Yes':
                    data['published_at'] = context['published_at'] = datetime.datetime.now()
                serializer = self.serializer_class(data=request.data, context=context)
                serializer.is_valid(raise_exception=True)
                serializer.save(user=self.request.user)
                return Response({'msg': 'Your blog is created'},
                                status=status.HTTP_201_CREATED)
            else:
                return Response({'msg': 'There must be a title for your blog.'},
                                status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(e)
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, blog_id, format=None):
        try:
            blog = Blog.objects.get(id=blog_id)
            if Blog.objects.filter(user=request.user).exists():
                data = request.data
                title_list = Blog.objects.filter(user=request.user).values_list('blog_title', flat=True)
                blog_title = request.POST.get('blog_title')
                if blog_title in title_list:
                    return Response({"Error": "You've already a blog with this title!"}, status=status.HTTP_404_NOT_FOUND)
                blog_image = request.POST.get('blog_image')
                blog_content = request.POST.get('blog_content')
                is_published = request.POST.get('is_published')
                
                context = {
                    'blog_title': blog_title,
                    'blog_image': blog_image,
                    'blog_content': blog_content,
                    'is_published': is_published,
                    # 'username': username,
                    'blog_id': blog_id,
                }
                if is_published == 'Yes':
                    data['published_at'] = context['published_at'] = datetime.datetime.now()
                
                serializer = BlogSerializer(blog, data=request.data, context=context, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save(user=self.request.user)
                return Response({'msg': 'Blog updated successfully.'},
                                status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(e)
            return Response(str(e), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, blog_id, format=None):
        
        if Blog.objects.filter(id=blog_id).exists():
            Blog.objects.get(id=blog_id).delete()
        else:
            raise serializers.ValidationError(
                "Blog doesn't exist")

        return Response({"Result": "Blog is deleted"}, status=status.HTTP_204_NO_CONTENT)


class PublishedBlogsView(GenericAPIView):
    renderer_classes = (UserRenderer,)
    # permission_classes = (IsAuthenticated,)
    serializer_class = BlogSerializer
    print('hola')

    def get(self, request, format=None):
        user = request.user
        print('i m also')
        import pdb; pdb.set_trace()
        blogs = Blog.objects.all()
        serializer = BlogSerializer(blogs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

