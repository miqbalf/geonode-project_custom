from rest_framework import serializers

from geonode.people.models import Profile


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        user = Profile.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            # disable direct login - enable approval moderation
            is_active=False,
        )
        return user