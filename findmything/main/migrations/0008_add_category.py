# Generated migration file

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0007_auto_20251208_2120'),
    ]

    operations = [
        migrations.AddField(
            model_name='lostitem',
            name='category',
            field=models.CharField(choices=[('Electronics', 'Electronics'), ('Documents', 'Documents'), ('Accessories', 'Accessories'), ('Clothing', 'Clothing'), ('Others', 'Others')], default='Others', max_length=50),
        ),
        migrations.AddField(
            model_name='founditem',
            name='category',
            field=models.CharField(choices=[('Electronics', 'Electronics'), ('Documents', 'Documents'), ('Accessories', 'Accessories'), ('Clothing', 'Clothing'), ('Others', 'Others')], default='Others', max_length=50),
        ),
    ]
