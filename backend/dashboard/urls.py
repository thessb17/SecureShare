from django.urls import path

from .admin_views import (
    AdminActionListView,
    AdminSecurityEventsView,
    AdminUserDetailView,
    AdminUserListView,
    AdminUserUnlockView,
)
from .views import AdminStatsView, DashboardStatsView

urlpatterns = [
    path("dashboard/stats/", DashboardStatsView.as_view(), name="dashboard-stats"),
    path("admin/stats/", AdminStatsView.as_view(), name="admin-stats"),
    path("admin/users/", AdminUserListView.as_view(), name="admin-users"),
    path("admin/users/<uuid:user_id>/", AdminUserDetailView.as_view(), name="admin-user-detail"),
    path("admin/users/<uuid:user_id>/unlock/", AdminUserUnlockView.as_view(), name="admin-user-unlock"),
    path("admin/security-events/", AdminSecurityEventsView.as_view(), name="admin-security-events"),
    path("admin/actions/", AdminActionListView.as_view(), name="admin-actions"),
]
