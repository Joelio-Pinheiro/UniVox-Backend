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

    #URL PARA TESTE
    path('users/', list_users),

    # --- Rotas de User ---
    path('users/create/', create_user),
    path('users/profile/update/', update_user_profile),
    path('users/deletename/', delete_user_by_name),
    path('users/deletelogged/', delete_user_logged),
    path('users/login/', login_user),
    path('users/logout/', logout_user),
    path('users/verifyemail/', verify_email),
    path('users/passwordresetreq/', reset_password_request),
    path('users/passwordresetvalidate/', reset_password_validate),
    path('users/passwordresetnewpass/', reset_password_chooseNew),
    path('users/passwordresetresend/', reset_password_resend),

    # --- Rotas de Posts ---
    path('posts/create/', create_post),
    path('posts/', list_posts), # Lista para testes
    path('posts/<int:post_id>/', view_post),

    # --- Rotas de Comentários ---
    path('posts/<int:post_id>/comment/', create_comment),

    # --- Rotas de Votos ---
    path('vote/<str:model_type>/<int:object_id>/', cast_vote),

    # --- Rotas de Tópicos (Tags) ---
    path('topics/', list_topics),
    path('topics/create/', create_topic),
    path('topics/<int:topic_id>/posts/', list_posts_by_topic),

     # --- Rotas de Edição e Deleção ---
    #Posts
    path('posts/<int:post_id>/update/', update_post),
    path('posts/<int:post_id>/delete/', delete_post),

    #Comentários (e Respostas)
    path('comments/<int:comment_id>/update/', update_comment),
    path('comments/<int:comment_id>/delete/', delete_comment),

     # --- Rotas de Perfil do Usuário ('Me') ---
    path('users/me/posts/', list_my_posts),
    path('users/me/comments/', list_my_comments),
    path('users/me/posts/<str:vote_type_filter>/', list_my_voted_posts),

    #Post stuff
]
