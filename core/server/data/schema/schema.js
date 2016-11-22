/*
:todo:
    why every table schema has a uuid field?
*/
module.exports = {
    posts: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},//:todo - where is this validations used
        title: {type: 'string', maxlength: 150, nullable: false},
        slug: {type: 'string', maxlength: 150, nullable: false, unique: true},
        markdown: {type: 'text', maxlength: 16777215, fieldtype: 'medium', nullable: true},//:todo: maxlength?
        mobiledoc: {type: 'text', maxlength: 1000000000, fieldtype: 'long', nullable: true},
        html: {type: 'text', maxlength: 16777215, fieldtype: 'medium', nullable: true},
        amp: {type: 'text', maxlength: 16777215, fieldtype: 'medium', nullable: true},
        image: {type: 'text', maxlength: 2000, nullable: true},
        featured: {type: 'bool', nullable: false, defaultTo: false},
        page: {type: 'bool', nullable: false, defaultTo: false},
        status: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'draft'},
        language: {type: 'string', maxlength: 6, nullable: false, defaultTo: 'en_US'},
        visibility: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'public', validations: {isIn: [['public']]}},
        meta_title: {type: 'string', maxlength: 150, nullable: true},
        meta_description: {type: 'string', maxlength: 200, nullable: true},
        author_id: {type: 'integer', nullable: false},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true},
        published_at: {type: 'dateTime', nullable: true},
        published_by: {type: 'integer', nullable: true}
    },
    users: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},//bm: validaiton is handle in ../validation module
        name: {type: 'string', maxlength: 150, nullable: false},
        slug: {type: 'string', maxlength: 150, nullable: false, unique: true},
        ghost_auth_access_token: {type: 'string', nullable: true},
        password: {type: 'string', maxlength: 60, nullable: false},
        email: {type: 'string', maxlength: 191, nullable: false, unique: true, validations: {isEmail: true}},
        image: {type: 'text', maxlength: 2000, nullable: true},
        cover: {type: 'text', maxlength: 2000, nullable: true},
        bio: {type: 'string', maxlength: 200, nullable: true},
        website: {type: 'text', maxlength: 2000, nullable: true, validations: {isEmptyOrURL: true}},
        location: {type: 'text', maxlength: 65535, nullable: true},
        facebook: {type: 'text', maxlength: 2000, nullable: true},
        twitter: {type: 'text', maxlength: 2000, nullable: true},
        accessibility: {type: 'text', maxlength: 65535, nullable: true},
        status: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'active'},
        language: {type: 'string', maxlength: 6, nullable: false, defaultTo: 'en_US'},
        visibility: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'public', validations: {isIn: [['public']]}},
        meta_title: {type: 'string', maxlength: 150, nullable: true},
        meta_description: {type: 'string', maxlength: 200, nullable: true},
        tour: {type: 'text', maxlength: 65535, nullable: true},
        last_login: {type: 'dateTime', nullable: true},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    roles: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},
        name: {type: 'string', maxlength: 150, nullable: false},
        description: {type: 'string', maxlength: 200, nullable: true},
        created_at: {type: 'dateTime',  nullable: false},
        created_by: {type: 'integer',  nullable: false},
        updated_at: {type: 'dateTime',  nullable: true},
        updated_by: {type: 'integer',  nullable: true}
    },
    roles_users: {
        id: {type: 'increments', nullable: false, primary: true},
        role_id: {type: 'integer', nullable: false},
        user_id: {type: 'integer', nullable: false}
    },
    permissions: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},
        name: {type: 'string', maxlength: 150, nullable: false},
        // action target. eg. post, tag, user, page
        object_type: {type: 'string', maxlength: 150, nullable: false},
        //edit, delete, create @see /permissions/index.js
        // defines various actions one can make.
        action_type: {type: 'string', maxlength: 150, nullable: false},
        object_id: {type: 'integer', nullable: true},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    permissions_users: {
        id: {type: 'increments', nullable: false, primary: true},
        user_id: {type: 'integer', nullable: false},
        permission_id: {type: 'integer', nullable: false}
    },
    permissions_roles: {
        id: {type: 'increments', nullable: false, primary: true},
        role_id: {type: 'integer', nullable: false},
        permission_id: {type: 'integer', nullable: false}
    },
    permissions_apps: {
        id: {type: 'increments', nullable: false, primary: true},
        app_id: {type: 'integer', nullable: false},
        permission_id: {type: 'integer', nullable: false}
    },
    settings: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},
        key: {type: 'string', maxlength: 150, nullable: false, unique: true},
        value: {type: 'text', maxlength: 65535, nullable: true},
        type: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'core', validations: {isIn: [['core', 'blog', 'theme', 'app', 'plugin', 'private']]}},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    tags: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},
        name: {type: 'string', maxlength: 150, nullable: false, validations: {matches: /^([^,]|$)/}},
        slug: {type: 'string', maxlength: 150, nullable: false, unique: true},
        description: {type: 'string', maxlength: 200, nullable: true},
        image: {type: 'text', maxlength: 2000, nullable: true},
        parent_id: {type: 'integer', nullable: true},
        visibility: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'public', validations: {isIn: [['public', 'internal']]}},
        meta_title: {type: 'string', maxlength: 150, nullable: true},
        meta_description: {type: 'string', maxlength: 200, nullable: true},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    posts_tags: {
        id: {type: 'increments', nullable: false, primary: true},
        post_id: {type: 'integer', nullable: false, unsigned: true, references: 'posts.id'},
        tag_id: {type: 'integer', nullable: false, unsigned: true, references: 'tags.id'},
        sort_order: {type: 'integer',  nullable: false, unsigned: true, defaultTo: 0}
    },
    apps: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},
        name: {type: 'string', maxlength: 150, nullable: false, unique: true},
        slug: {type: 'string', maxlength: 150, nullable: false, unique: true},
        version: {type: 'string', maxlength: 150, nullable: false},
        status: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'inactive'},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    app_settings: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},
        key: {type: 'string', maxlength: 150, nullable: false, unique: true},
        value: {type: 'text', maxlength: 65535, nullable: true},
        app_id: {type: 'integer', nullable: false, unsigned: true, references: 'apps.id'},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    app_fields: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},
        key: {type: 'string', maxlength: 150, nullable: false},
        value: {type: 'text', maxlength: 65535, nullable: true},
        type: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'html'},
        app_id: {type: 'integer', nullable: false, unsigned: true, references: 'apps.id'},
        relatable_id: {type: 'integer', nullable: false, unsigned: true},
        relatable_type: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'posts'},
        active: {type: 'bool', nullable: false, defaultTo: true},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    clients: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false},
        name: {type: 'string', maxlength: 150, nullable: false, unique: true},
        slug: {type: 'string', maxlength: 150, nullable: false, unique: true},
        secret: {type: 'string', maxlength: 150, nullable: false},
        redirection_uri: {type: 'string', maxlength: 2000, nullable: true},
        logo: {type: 'string', maxlength: 2000, nullable: true},
        status: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'development'},
        type: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'ua', validations: {isIn: [['ua', 'web', 'native']]}},
        description: {type: 'string', maxlength: 200, nullable: true},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    client_trusted_domains: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false},
        client_id: {type: 'integer', nullable: false, unsigned: true, references: 'clients.id'},
        trusted_domain: {type: 'string', maxlength: 2000, nullable: true}
    },
    accesstokens: {
        id: {type: 'increments', nullable: false, primary: true},
        token: {type: 'string', maxlength: 191, nullable: false, unique: true},
        user_id: {type: 'integer', nullable: false, unsigned: true, references: 'users.id'},
        client_id: {type: 'integer', nullable: false, unsigned: true, references: 'clients.id'},
        expires: {type: 'bigInteger', nullable: false}
    },
    refreshtokens: {
        id: {type: 'increments', nullable: false, primary: true},
        token: {type: 'string', maxlength: 191, nullable: false, unique: true},
        user_id: {type: 'integer', nullable: false, unsigned: true, references: 'users.id'},
        client_id: {type: 'integer', nullable: false, unsigned: true, references: 'clients.id'},
        expires: {type: 'bigInteger', nullable: false}
    },
    subscribers: {
        id: {type: 'increments', nullable: false, primary: true},
        uuid: {type: 'string', maxlength: 36, nullable: false, validations: {isUUID: true}},
        name: {type: 'string', maxlength: 150, nullable: true},
        email: {type: 'string', maxlength: 191, nullable: false, unique: true, validations: {isEmail: true}},
        status: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'pending', validations: {isIn: [['subscribed', 'pending', 'unsubscribed']]}},
        post_id: {type: 'integer', nullable: true, unsigned: true, references: 'posts.id'},
        subscribed_url: {type: 'text', maxlength: 2000, nullable: true, validations: {isEmptyOrURL: true}},
        subscribed_referrer: {type: 'text', maxlength: 2000, nullable: true, validations: {isEmptyOrURL: true}},
        unsubscribed_url: {type: 'text', maxlength: 2000, nullable: true, validations: {isEmptyOrURL: true}},
        unsubscribed_at: {type: 'dateTime', nullable: true},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    invites: {
        id: {type: 'increments', nullable: false, primary: true},
        status: {type: 'string', maxlength: 150, nullable: false, defaultTo: 'pending', validations: {isIn: [['pending', 'sent']]}},
        token: {type: 'string', maxlength: 191, nullable: false, unique: true},
        email: {type: 'string', maxlength: 191, nullable: false, unique: true, validations: {isEmail: true}},
        expires: {type: 'bigInteger', nullable: false},
        created_at: {type: 'dateTime', nullable: false},
        created_by: {type: 'integer', nullable: false},
        updated_at: {type: 'dateTime', nullable: true},
        updated_by: {type: 'integer', nullable: true}
    },
    invites_roles: {
        id: {type: 'increments', nullable: false, primary: true},
        role_id: {type: 'integer', nullable: false},
        invite_id: {type: 'integer', nullable: false}
    }
};
