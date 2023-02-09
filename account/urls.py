from django.urls import path
from .views import UserRegistrationView, UserLoginView, VerifyOTP, CreateNewBlog, \
PublishedBlogsView


urlpatterns = [
    # path('verify-uid-token/', VerifyUIDTokenView.as_view(), name='verify-uid-token'),
    path('register/', UserRegistrationView.as_view()),
    path('login/', UserLoginView.as_view()),
    path('verify/', VerifyOTP.as_view()),
    path('blog-list/', CreateNewBlog.as_view(), name='blog-list'),
    path('edit-blog/', CreateNewBlog.as_view(), name='edit-blog'),
    path('edit-blog/<int:blog_id>/', CreateNewBlog.as_view(), name='edit-blog'),
    path('delete-blog/<int:blog_id>/', CreateNewBlog.as_view(), name='delete-blog'),
    # path('view-blog/', CreateNewBlog.as_view(), name='view-blog'),
    path('home/', PublishedBlogsView.as_view()),

    # path('<str:username>/', CreateNewBlog.as_view()),
    # path('<str:username>/blogs/', CreateNewBlog.as_view()),
    # path('<str:username>/<int:blog_id>/', CreateNewBlog.as_view()),
    # path('home/', PublishedBlogsView.as_view()),
    
    # path('user-details/', UserView.as_view()),
    # path('logout/', UserLogoutView.as_view()),
]
