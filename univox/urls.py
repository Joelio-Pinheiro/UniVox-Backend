from django.contrib import admin
from django.urls import path, include
from core.views import *

from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Your API Title",
        default_version='v1',
        description="API documentation with Swagger UI",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="you@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
    url='https://univox-backend.onrender.com', 
)

urlpatterns = [
    path('admin/', admin.site.urls),

    #Swagger
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    #User stuff
    path('users/create/', create_user),
    path('users/delete/', delete_user),
    path('users/login/', login_user),
    path('users/logout/', logout_user),
    path('users/verifyemail/', verify_email),
    path('users/passwordresetreq/', reset_password_request),
    path('users/passwordresetvalidate/', reset_password_validate),
    path('users/passwordresetnewpass/', reset_password_chooseNew),

    #Post stuff
    
]
