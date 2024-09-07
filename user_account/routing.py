from django.urls import path
from . import consumers


websocket_urlpatterns = [
    path("user/chat/", consumers.ChatConsumer.as_asgi()),
    path("user/chat/<int:thread_id>/", consumers.ChatConsumer.as_asgi()),
]