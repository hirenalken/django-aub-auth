from rest_framework import serializers

from drf_auth_users.models import OAuthUsers, User


class UserRegistrationSerializer(serializers.Serializer):
    """
        Serializer for user registration request data
    """

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    email = serializers.EmailField(max_length=256)
    first_name = serializers.CharField(allow_blank=True)
    last_name = serializers.CharField(allow_blank=True)
    password = serializers.CharField(max_length=256)


class UserLoginSerializer(serializers.Serializer):
    """
        Serializer for user registration request data
    """

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    email = serializers.EmailField(max_length=256)
    password = serializers.CharField(max_length=256)


class UserOAuthSerializer(serializers.ModelSerializer):
    class Meta:
        model = OAuthUsers
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ('password',)


class UserOAuthRequestSerializer(serializers.Serializer):
    oauth_user = serializers.CharField()
    oauth_provider = serializers.IntegerField()
    access_token = serializers.CharField(max_length=800)
    long_lived_access_token = serializers.CharField(max_length=800, required=False)
    email = serializers.EmailField(max_length=256)

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass