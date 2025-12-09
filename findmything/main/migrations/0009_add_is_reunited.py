from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0008_add_category'),
    ]

    operations = [
        migrations.AddField(
            model_name='lostitem',
            name='is_reunited',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='founditem',
            name='is_reunited',
            field=models.BooleanField(default=False),
        ),
    ]
