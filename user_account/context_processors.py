# user_account/context_processors.py
from .models import Notification

def notifications_processor(request):
    if request.user.is_authenticated:
        notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[:5]
    else:
        notifications = []
    return {'notifications': notifications}
