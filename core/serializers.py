from rest_framework import serializers
from django.core.validators import validate_email
from .models import User, EmailConfirmation
from univox.email import generate_confirmation_code, send_confirmation_email
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from .models import User

from .models import User, EmailConfirmation, Post, Comment, Vote, Topic
from univox.email import generate_confirmation_code, send_confirmation_email

def validate_post_data(data):
    """Função reutilizável para validar dados de post."""
    # Validação do Título
    title = data.get('title')
    if title is not None and not (1 <= len(title) <= 100):
        raise serializers.ValidationError({'title': 'O título deve ter entre 1 e 100 caracteres.'})

    # Validação do Conteúdo
    content = data.get('content')
    if content is not None and not (1 <= len(content) <= 600):
        raise serializers.ValidationError({'content': 'O conteúdo deve ter entre 1 e 600 caracteres.'})

    # Validação do número de Tags
    topics = data.get('topics')
    if topics is not None and len(topics) > 5:
        raise serializers.ValidationError({'topics': 'Você pode adicionar no máximo 5 tags.'})
    
    return data

# ---- Get de Usuários para teste ----
class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'avatar_id','name', 'user_name', 'email', 'email_verified', 'description', 'created_at']

class CreateUserSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField()
    contact_number = serializers.CharField(max_length=20)

class UpdateUserSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=50, required=False)
    user_name = serializers.CharField(max_length=50, required=False)
    description = serializers.CharField(max_length=200, required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True, required=False)

    avatar_id = serializers.IntegerField(min_value=1, max_value=4, required=False)

    def validate(self, data):
        instance = self.instance

        if 'name' in data and User.objects.filter(name__iexact=data['name']).exclude(pk=instance.pk).exists():
            raise serializers.ValidationError({'error': 'Esse nome já está em uso.'})
        
        if 'user_name' in data and User.objects.filter(user_name__iexact=data['user_name']).exclude(pk=instance.pk).exists():
            raise serializers.ValidationError({'error': 'Esse username já está em uso.'})

        if 'email' in data and User.objects.filter(email__iexact=data['email']).exclude(pk=instance.pk).exists():
            raise serializers.ValidationError({'error': 'Esse email já está em uso.'})
            
        return data

    def validate_user_name(self, value):
        if not value.startswith('@'):
            value = f'@{value}'
        return value

    def update(self, instance, validated_data):

        instance._email_changed = False 


        new_email = validated_data.get('email')
        if new_email and new_email != instance.email:
            instance.email = new_email
            instance.email_verified = False
            code = generate_confirmation_code()
            EmailConfirmation.objects.update_or_create(
                user=instance,
                defaults={'code': code, 'created_at': timezone.now(), 'is_confirmed': False}
            )
            send_confirmation_email(instance, code)

            instance._email_changed = True


        if 'password' in validated_data:
            instance.password = make_password(validated_data['password'])
        
        instance.name = validated_data.get('name', instance.name)
        instance.user_name = validated_data.get('user_name', instance.user_name)
        instance.description = validated_data.get('description', instance.description)
        instance.email = validated_data.get('email', instance.email)
        
        instance.save()
        return instance

class DeleteUserSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=150)

class DeleteUserAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)


class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordValidateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)

class ResetPasswordChooseNewSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)

class ResetPasswordResend(serializers.Serializer):
    email = serializers.EmailField()

class UserPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'user_name']

class TopicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Topic
        fields = ['id', 'name']
        read_only_fields = ['id']

    def validate_name(self, value):
        cleaned_name = value.strip()
        if not cleaned_name.startswith('#'):
            formatted_name = f"#{cleaned_name}"
        else:
            formatted_name = cleaned_name
        
        if Topic.objects.filter(name__iexact=formatted_name).exists():
            raise serializers.ValidationError("Este tópico já existe.")
        
        return formatted_name

class ReplySerializer(serializers.ModelSerializer):
    creator = UserPublicSerializer(read_only=True)
    
    class Meta:
        model = Comment
        fields = ['id', 'creator', 'content', 'created_at', 'is_edited', 'is_deleted', 'upvotes', 'downvotes', 'replies']

    def get_fields(self):
        fields = super().get_fields()
        fields['replies'] = ReplySerializer(many=True, read_only=True)
        return fields

class CommentSerializer(serializers.ModelSerializer):
    creator = UserPublicSerializer(read_only=True)
    replies = ReplySerializer(many=True, read_only=True)

    class Meta:
        model = Comment
        fields = ['id', 'creator', 'content', 'created_at', 'is_edited', 'is_deleted', 'upvotes', 'downvotes', 'replies']

class PostDetailSerializer(serializers.ModelSerializer):
    creator = UserPublicSerializer(read_only=True)
    topics = TopicSerializer(many=True, read_only=True)
    comments = CommentSerializer(many=True, read_only=True)
    comment_count = serializers.SerializerMethodField()

    class Meta:
        model = Post
        fields = ['id', 'creator', 'topics', 'title', 'content', 'created_at', 'is_edited', 'is_deleted', 'upvotes', 'downvotes', 'comment_count', 'comments']
    
    def get_comment_count(self, obj):
        return obj.comments.filter(is_deleted=False).count()

class PostCreateSerializer(serializers.ModelSerializer):
    topics = serializers.ListField(
        child=serializers.CharField(max_length=50),
        required=False,
        write_only=True
    )

    class Meta:
        model = Post
        fields = ['title', 'content', 'topics', 'is_anonymous']

    def validate(self, data):
        return validate_post_data(data)

    def create(self, validated_data):
        topics_data = validated_data.pop('topics', [])
        post = Post.objects.create(**validated_data)
        for topic_name in topics_data:
            cleaned_name = topic_name.strip()
            if not cleaned_name.startswith('#'):
                formatted_name = f"#{cleaned_name}"
            else:
                formatted_name = cleaned_name
            topic, created = Topic.objects.get_or_create(
                name__iexact=formatted_name, 
                defaults={'name': formatted_name}
            )
            post.topics.add(topic)
        return post

class CommentCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['content', 'parent_comment']

    def validate_content(self, value):
        if not (1 <= len(value) <= 300):
            raise serializers.ValidationError('O comentário deve ter entre 1 e 300 caracteres.')
        return value

class VoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vote
        fields = ['vote_type']
        
    def validate_vote_type(self, value):
        if value not in [Vote.VoteType.UPVOTE, Vote.VoteType.DOWNVOTE]:
            raise serializers.ValidationError("Tipo de voto inválido. Use 1 para upvote ou -1 para downvote.")
        return value
    
class PostUpdateSerializer(serializers.ModelSerializer):
    topics = serializers.ListField(
        child=serializers.CharField(max_length=50),
        required=False,
        write_only=True
    )

    class Meta:
        model = Post
        fields = ['title', 'content', 'topics']

    def validate(self, data):
        return validate_post_data(data)

    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.content = validated_data.get('content', instance.content)
        if 'topics' in validated_data:
            topics_data = validated_data.pop('topics')
            instance.topics.clear()
            for topic_name in topics_data:
                cleaned_name = topic_name.strip()
                if not cleaned_name.startswith('#'):
                    formatted_name = f"#{cleaned_name}"
                else:
                    formatted_name = cleaned_name
                topic, created = Topic.objects.get_or_create(
                    name__iexact=formatted_name,
                    defaults={'name': formatted_name}
                )
                instance.topics.add(topic)
        instance.is_edited = True
        instance.save()
        return instance

class CommentUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['content']

    def validate_content(self, value):
        if not (1 <= len(value) <= 300):
            raise serializers.ValidationError('O comentário deve ter entre 1 e 300 caracteres.')
        return value
    
    def update(self, instance, validated_data):
        instance.content = validated_data.get('content', instance.content)
        instance.is_edited = True
        instance.save()
        return instance
    
class PostListSerializer(serializers.ModelSerializer):
    creator = UserPublicSerializer(read_only=True)
    topics = TopicSerializer(many=True, read_only=True)
    comment_count = serializers.SerializerMethodField()

    class Meta:
        model = Post
        fields = [
            'id', 
            'title', 
            'creator', 
            'topics', 
            'created_at', 
            'upvotes', 
            'downvotes', 
            'comment_count'
        ]

    def get_comment_count(self, obj):
        return obj.comments.filter(is_deleted=False).count()