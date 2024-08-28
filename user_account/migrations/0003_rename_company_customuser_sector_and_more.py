# Generated by Django 4.2 on 2024-07-22 08:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_account', '0002_review'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customuser',
            old_name='company',
            new_name='sector',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='i_can',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='looking_for',
        ),
        migrations.AddField(
            model_name='customuser',
            name='cv',
            field=models.FileField(blank=True, null=True, upload_to='cv/'),
        ),
    ]
