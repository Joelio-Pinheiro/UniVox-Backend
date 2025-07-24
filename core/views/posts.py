from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from django.shortcuts import get_object_or_404
from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from ..models import User, Post, Comment, Vote, Topic

from ..serializers import (
    PostCreateSerializer, PostDetailSerializer, CommentCreateSerializer, VoteSerializer, TopicSerializer,
    CommentSerializer, PostUpdateSerializer, CommentUpdateSerializer, PostListSerializer
)

# ---- Criação de Posts ----
@swagger_auto_schema(method='post', request_body=PostCreateSerializer)
@api_view(['POST'])
def create_post(request):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    serializer = PostCreateSerializer(data=request.data)
    if serializer.is_valid():
        user = get_object_or_404(User, id=request.session.get('user_id'))
        post = serializer.save(creator=user)
        return Response(PostDetailSerializer(post).data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ---- Vizualização de um Post ----
@api_view(['GET'])
def view_post(request, post_id):
    post = get_object_or_404(Post, id=post_id, is_deleted=False)
    top_level_comments = post.comments.filter(parent_comment__isnull=True, is_deleted=False)
    serializer = PostDetailSerializer(post)
    data = serializer.data
    data['comments'] = CommentSerializer(top_level_comments, many=True).data
    return Response(data)

# ---- Lista de Posts (Testes) ----
@api_view(['GET'])
def list_posts(request):

    posts = Post.objects.filter(is_deleted=False).order_by('-created_at')
    
    serializer = PostListSerializer(posts, many=True)
    
    return Response(serializer.data)

# ---- Lista de Posts por Tópicos ----
@api_view(['GET'])
def list_posts_by_topic(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
    posts = topic.posts.filter(is_deleted=False)
    serializer = PostDetailSerializer(posts, many=True)
    return Response(serializer.data)

# ---- Lista de Posts do usuário ----
@api_view(['GET'])
def list_my_posts(request):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    user = get_object_or_404(User, id=request.session.get('user_id'))
    
    posts = Post.objects.filter(creator=user, is_deleted=False).order_by('-created_at')
    serializer = PostListSerializer(posts, many=True)
    
    return Response(serializer.data)

# ---- Lista de Posts votados pelo usuário (upvote, downvote) ----
@api_view(['GET'])
def list_my_voted_posts(request, vote_type_filter):

    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    user = get_object_or_404(User, id=request.session.get('user_id'))
    
    if vote_type_filter == 'upvoted':
        vote_type = Vote.VoteType.UPVOTE
    elif vote_type_filter == 'downvoted':
        vote_type = Vote.VoteType.DOWNVOTE
    else:
        return Response({'error': 'Filtro de voto inválido.'}, status=status.HTTP_400_BAD_REQUEST)

    post_content_type = ContentType.objects.get_for_model(Post)
    voted_post_ids = Vote.objects.filter(
        user=user,
        vote_type=vote_type,
        content_type=post_content_type
    ).values_list('object_id', flat=True)

    posts = Post.objects.filter(id__in=voted_post_ids, is_deleted=False).order_by('-created_at')
    serializer = PostListSerializer(posts, many=True)
    
    return Response(serializer.data)

# ---- Update de Posts ----
@swagger_auto_schema(method='patch', request_body=PostUpdateSerializer)
@api_view(['PATCH'])
def update_post(request, post_id):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    post = get_object_or_404(Post, id=post_id, is_deleted=False)
    user = get_object_or_404(User, id=request.session.get('user_id'))

    if post.creator != user:
        return Response({'error': 'Você não tem permissão para editar este post.'}, status=status.HTTP_403_FORBIDDEN)

    serializer = PostUpdateSerializer(instance=post, data=request.data, partial=True)
    if serializer.is_valid():
        updated_post = serializer.save()
        return Response(PostDetailSerializer(updated_post).data)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ---- Delete de Posts ----
@api_view(['DELETE'])
def delete_post(request, post_id):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)

    post = get_object_or_404(Post, id=post_id)
    user = get_object_or_404(User, id=request.session.get('user_id'))

    if post.creator != user:
        return Response({'error': 'Você não tem permissão para deletar este post.'}, status=status.HTTP_403_FORBIDDEN)
    
    post.is_deleted = True
    post.save(update_fields=['is_deleted'])
    
    return Response(status=status.HTTP_204_NO_CONTENT)

# ---- Criação de Comments ----
@swagger_auto_schema(method='post', request_body=CommentCreateSerializer)
@api_view(['POST'])
def create_comment(request, post_id):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)

    post = get_object_or_404(Post, id=post_id, is_deleted=False)
    user = get_object_or_404(User, id=request.session.get('user_id'))

    serializer = CommentCreateSerializer(data=request.data)
    if serializer.is_valid():
        comment = serializer.save(creator=user, post=post)
        return Response(CommentSerializer(comment).data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ---- Criação de Comments do usuário ----
@api_view(['GET'])
def list_my_comments(request):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    user = get_object_or_404(User, id=request.session.get('user_id'))
    
    comments = Comment.objects.filter(creator=user, is_deleted=False).order_by('-created_at')
    
    serializer = CommentSerializer(comments, many=True)
    
    return Response(serializer.data)

# ---- Update de Comments ----
@swagger_auto_schema(method='patch', request_body=CommentUpdateSerializer)
@api_view(['PATCH'])
def update_comment(request, comment_id):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    comment = get_object_or_404(Comment, id=comment_id, is_deleted=False)
    user = get_object_or_404(User, id=request.session.get('user_id'))

    if comment.creator != user:
        return Response({'error': 'Você não tem permissão para editar este comentário.'}, status=status.HTTP_403_FORBIDDEN)

    serializer = CommentUpdateSerializer(instance=comment, data=request.data, partial=True)
    if serializer.is_valid():
        updated_comment = serializer.save()
        return Response(CommentSerializer(updated_comment).data)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ---- Delete de Comments ----
@api_view(['DELETE'])
def delete_comment(request, comment_id):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    comment = get_object_or_404(Comment, id=comment_id)
    user = get_object_or_404(User, id=request.session.get('user_id'))

    if comment.creator != user:
        return Response({'error': 'Você não tem permissão para deletar este comentário.'}, status=status.HTTP_403_FORBIDDEN)
    
    comment.is_deleted = True
    comment.content = "[Comentário removido pelo autor]"
    comment.save(update_fields=['is_deleted', 'content'])
    
    return Response(status=status.HTTP_204_NO_CONTENT)

# ---- Criação de topic ----
@swagger_auto_schema(method='post', request_body=TopicSerializer)
@api_view(['POST'])
def create_topic(request):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    serializer = TopicSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ---- Lista de topic ----
@api_view(['GET'])
def list_topics(request):
    topics = Topic.objects.all().order_by('name')
    serializer = TopicSerializer(topics, many=True)
    return Response(serializer.data)

# ---- Utilização de Upvote e Downvote ----
@swagger_auto_schema(method='post', request_body=VoteSerializer)
@api_view(['POST'])
def cast_vote(request, model_type, object_id):
    if not request.session.get('logged'):
        return Response({'error': 'Autenticação necessária.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    Model = Post if model_type == 'post' else Comment if model_type == 'comment' else None
    if not Model:
        return Response({'error': 'Tipo de objeto inválido.'}, status=status.HTTP_400_BAD_REQUEST)

    content_object = get_object_or_404(Model, id=object_id)
    user = get_object_or_404(User, id=request.session.get('user_id'))
    
    serializer = VoteSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    vote_type = serializer.validated_data['vote_type']
    content_type = ContentType.objects.get_for_model(Model)

    try:
        with transaction.atomic():
            existing_vote = Vote.objects.filter(user=user, content_type=content_type, object_id=object_id).first()

            if not existing_vote:
                if vote_type == Vote.VoteType.UPVOTE:
                    content_object.upvotes += 1
                else:
                    content_object.downvotes += 1
                Vote.objects.create(user=user, content_object=content_object, vote_type=vote_type)

            else:
                if existing_vote.vote_type == vote_type:
                    if vote_type == Vote.VoteType.UPVOTE:
                        if content_object.upvotes > 0: content_object.upvotes -= 1
                    else:
                        if content_object.downvotes > 0: content_object.downvotes -= 1
                    existing_vote.delete()
                
                else:
                    if vote_type == Vote.VoteType.UPVOTE:
                        if content_object.downvotes > 0: content_object.downvotes -= 1
                        content_object.upvotes += 1
                    else:
                        if content_object.upvotes > 0: content_object.upvotes -= 1
                        content_object.downvotes += 1
                    
                    existing_vote.vote_type = vote_type
                    existing_vote.save()

            content_object.save(update_fields=['upvotes', 'downvotes'])
            
        return Response({
            'message': 'Voto registrado!', 
            'upvotes': content_object.upvotes,
            'downvotes': content_object.downvotes,
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': f'Ocorreu um erro: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)