# Generated by Django 4.2 on 2024-09-07 06:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_account', '0008_notification'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notification',
            name='message',
            field=models.TextField(),
        ),
    ]
