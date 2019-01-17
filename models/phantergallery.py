# -*- coding: utf-8 -*-
from ..models import db
from pydal import Field
import os

db.define_table('phantergallery',
    Field('folder'),
    Field('filename'),
    Field('extensao')
    )

db.define_table('auth_user_phantergallery',
    Field('phantergallery', 'reference phantergallery'),
    Field('auth_user', 'reference auth_user'),
    Field('subfolder'),
    )

class UserImage():
    db = db
    def __init__ (self, id_user, upload_folder='uploads'):
        self.db._adapter.reconnect()
        self.id_user = id_user
        self.upload_folder = upload_folder

    @property
    def image(self):
        q_imagem = self.db(
            db.auth_user_phantergallery.auth_user == self.id_user
        ).select().first()
        if q_imagem:
            db.phantergallery[q_imagem.phantergallery]
            self._image = db.phantergallery[q_imagem.phantergallery]
        else:
            self._image = None
        return self._image

    def set_image(self, file, filename, extensao):
        target_folder = os.path.join(self.upload_folder,"user_%s" % self.id_user,'profile')
        os.makedirs(target_folder, exist_ok=True)
        q_image = self.db(
                (db.auth_user_phantergallery.auth_user==self.id_user)&(db.auth_user_phantergallery.subfolder=='profile')
            ).select()
        if q_image:
            for q in q_image:
                try:
                    os.remove(os.path.join(target_folder, "%s.%s" % (q.phantergallery.id, q.phantergallery.extensao)))
                except OSError:
                    pass
                db(db.phantergallery.id==q.phantergallery.id).select().first().delete_record()
            db.commit()
        id_new_image = self.db.phantergallery.insert(folder=target_folder,
                                  filename=filename,
                                  extensao=extensao)
        if id_new_image:
            with open(
                    os.path.join(target_folder, "%s.%s" % (id_new_image, extensao)),
                    'wb') as new_image:
                new_image.write(file)
            new_vinculo = db.auth_user_phantergallery.insert(
                    phantergallery = id_new_image,
                    auth_user = self.id_user,
                    subfolder = "profile"
                )
            if new_vinculo:
                db.commit()


class PhanterGalleryUpload(object):
    db = db
    def __init__(self,
                 id=None):
        super(PhanterGalleryUpload, self).__init__()
        self.db._adapter.reconnect()
        self.id = id

    def insert_or_update(self, file, folder, filename, extensao):
        os.makedirs(folder, exist_ok=True)
        q_image = self.db(db.phantergallery.id==self.id).select().first()
        if q_image:
            try:
                os.remove(os.path.join(folder, "%s.%s" % (q_image.id, q_image.extensao)))
            except OSError:
                pass
            q_image.update_record(folder=folder,
                                  filename=filename,
                                  extensao=extensao)
            with open(
                    os.path.join(folder, "%s.%s" % (q_image.id, extensao)),
                    'wb') as new_image:
                new_image.write(file)
            db.commit()
        else:
            id_image = self.db.phantergallery.insert(folder=folder,
                                  filename=filename,
                                  extensao=extensao)
            if id_image:
                db.commit()
                self.id = id_image
                with open(
                        os.path.join(folder, "%s.%s" % (id_image, extensao)),
                        'wb') as new_image:
                    new_image.write(file)
        return self.id

    def delete(self):
        q_image = self.db(db.phantergallery.id==self.id).select().first()
        if q_image:
            try:
                os.remove(os.path.join(q_image.folder, "%s.%s" % (q_image.id, q_image.extensao)))
            except OSError:
                pass
            q_image.delete_record()
            db.commit()
