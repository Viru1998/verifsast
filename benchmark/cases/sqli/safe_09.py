# CWE-89: Safe — Django ORM .filter() (no raw SQL)
# Django's ORM generates parameterised queries; user input is never placed
# directly into a SQL string.

# NOTE: this file demonstrates the pattern without a running Django project.
# In a real Django app these imports would resolve normally.

try:
    from django.db import models

    class User(models.Model):
        username = models.CharField(max_length=150)
        email = models.EmailField()
        is_active = models.BooleanField(default=True)

        class Meta:
            app_label = "benchmark"

    class Order(models.Model):
        user = models.ForeignKey(User, on_delete=models.CASCADE)
        status = models.CharField(max_length=50)
        total = models.DecimalField(max_digits=10, decimal_places=2)

        class Meta:
            app_label = "benchmark"

    def find_user(username):
        """SAFE: Django ORM filter — parameterised under the hood."""
        return User.objects.filter(username=username, is_active=True).first()

    def list_orders(user_id, status):
        """SAFE: chained ORM filters."""
        return Order.objects.filter(user_id=user_id, status=status).order_by("-id")

    def search_users(query):
        """SAFE: icontains generates a LIKE with parameterised binding."""
        return User.objects.filter(username__icontains=query)

except ImportError:
    # Django not installed in this environment — pattern is what matters.
    def find_user(username):  # type: ignore
        raise NotImplementedError("Django required")

    def list_orders(user_id, status):  # type: ignore
        raise NotImplementedError("Django required")

    def search_users(query):  # type: ignore
        raise NotImplementedError("Django required")


if __name__ == "__main__":
    print("Django ORM safe pattern — no injection possible via .filter()")
