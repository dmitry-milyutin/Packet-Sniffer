from django.db import models
from django.urls import reverse


class Capture(models.Model):
    """
    One uploaded capture file.

    The analysis isn't stored -- it's recomputed when the report page loads.
    Fine for small captures, and keeps the schema to one model. If reports get
    slow, cached results go here.
    """

    file = models.FileField(upload_to="captures/%Y/%m/%d/")
    original_name = models.CharField(max_length=255)
    size_bytes = models.BigIntegerField(default=0)
    uploaded_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self):
        return self.original_name

    def get_absolute_url(self):
        return reverse("report", args=[self.pk])