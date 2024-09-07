from django.views import View
from django.db.models import F
from django.db import transaction
from django.http import JsonResponse
from django.db.models import Avg, Count
from user_account.models import CustomUser, Review
from .models import CommunityCategory, CommunityPost
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_POST
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q


@login_required(login_url='signin')
def Community(request):
    communities = CommunityCategory.objects.all()
    CategoryName = request.GET.get('community', None)
    search_filter = request.GET.get('search_filter', None)
    
    if CategoryName:
        category = CommunityCategory.objects.get(name=CategoryName)
        posts = CommunityPost.objects.filter(category=category)
    elif search_filter:
        posts = CommunityPost.objects.filter(
            Q(title__icontains=search_filter) |
            Q(user__full_name__icontains=search_filter) |
            Q(user__zip_code__icontains=search_filter)
        )
    else:
        posts = CommunityPost.objects.all()
    
    paginator = Paginator(posts, 10)
    page_number = request.GET.get('page')
    
    try:
        paginated_posts = paginator.page(page_number)
    except PageNotAnInteger:
        paginated_posts = paginator.page(1)
    except EmptyPage:
        paginated_posts = paginator.page(paginator.num_pages)
    
    context = {
        'communities': communities,
        'posts': posts,
        'paginated_posts': paginated_posts,
    }
    
    return render(request, 'community.html', context)




@method_decorator(login_required(login_url='signin'), name='dispatch')
class CommunitySingle(View):
    def get(self, request, slug):
        post = get_object_or_404(CommunityPost, slug=slug)
        user = get_object_or_404(CustomUser, username=post.user)
        reviews = Review.objects.filter(reviewed_user=user)
        
        avg_rating = reviews.aggregate(Avg('rating'))['rating__avg'] or 0
        rating_counts = reviews.values('rating').annotate(count=Count('rating')).order_by('rating')
        
        context = {
            'user_data': user,
            'post': post,
            'reviews': reviews,
            'avg_rating': avg_rating,
            'rating_counts': rating_counts,
        }
        
        return render(request, 'community-post.html', context)

@require_POST
def like_post(request, post_id):
    try:
        post = CommunityPost.objects.get(id=post_id)
        post.likes += 1
        post.save()
        return JsonResponse({'likes': post.likes, 'dislikes': post.dislikes})
    except CommunityPost.DoesNotExist:
        return JsonResponse({'error': 'Post not found'}, status=404)

@require_POST
def dislike_post(request, post_id):
    try:
        post =CommunityPost.objects.get(id=post_id)
        post.dislikes += 1
        post.save()
        return JsonResponse({'likes': post.likes, 'dislikes': post.dislikes})
    except CommunityPost.DoesNotExist:
        return JsonResponse({'error': 'Post not found'}, status=404)

