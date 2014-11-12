#define NUA_MAGIC_T struct app
#define NUA_HMAGIC_T struct op
#define SU_ROOT_MAGIC_T struct app

#include <sofia-sip/sip_extra.h>
#include <sofia-sip/nua.h>
#include <stdlib.h>
#include <syslog.h>

struct vlog {
    enum {
        NONE = 0,
        SYSLOG = 1,
        STDIO = 2,
    } target;
    union {
        struct {
            FILE *stream;
        } stdio;
    };
} vlog;

void
__vlog(int level, const char *fmt, va_list ap)
{
    const char *prefix[] = {
        [LOG_EMERG]   = "A",
        [LOG_ALERT]   = "A",
        [LOG_CRIT]    = "E",
        [LOG_ERR]     = "E",
        [LOG_WARNING] = "W",
        [LOG_NOTICE]  = "N",
        [LOG_INFO]    = "I",
        [LOG_DEBUG]   = "D",
    };

    switch (vlog.target) {
    case SYSLOG:
        vsyslog(level, fmt, ap);
        break;
    case STDIO:
        fprintf(vlog.stdio.stream, "%s: ", prefix[level]);
        vfprintf(vlog.stdio.stream, fmt, ap);
        break;
    default:
        break;
    }
}

void
__attribute__((format (printf, 2, 3)))
__log(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    __vlog(level, fmt, ap);
    va_end(ap);
}

#define debug(_fmt, _args ...) __log(LOG_DEBUG, _fmt, ##_args)
#define info(_fmt, _args ...) __log(LOG_INFO, _fmt, ##_args)
#define notice(_fmt, _args ...) __log(LOG_NOTICE, _fmt, ##_args)
#define err(_fmt, _args ...) __log(LOG_ERR, _fmt, ##_args)

struct app {
    const char *user;
    const char *pass;
    const char *realm;
    const char *server;
    const char *dst;
    su_home_t *home;
    su_root_t *root;
    nua_t *nua;
};

struct op {
    nua_handle_t *nh;
    int status;
    int auth;
};

struct timeo {
    int done;
    struct app *app;
};

static void
authenticate(nua_handle_t *nh,
             const char *scheme,
             const char *realm,
             const char *user,
             const char *pass)
{
    char auth[256];

    snprintf(auth, sizeof(auth),
             "%s:\"%s\":%s:%s", scheme, realm, user, pass);

    nua_authenticate(nh, NUTAG_AUTH(auth), TAG_END());
}

static void
inv_event(nua_event_t event,
          int status,
          char const *phrase,
          nua_t *nua,
          struct app *app,
          nua_handle_t *nh,
          struct op *op,
          sip_t const *sip,
          tagi_t tags[])
{
    debug("EVENT %s %d %s\n",
          nua_event_name(event), status, phrase);

    if (op) {
        if (status == 401) {
            if (op->status / 100 != 4)
                authenticate(nh, "Digest",
                             app->realm, app->user, app->pass);
            else
                su_root_break(app->root);
        }

        op->status = status;
    }

    switch (event) {
    case nua_r_register:
        if (status == 200)
            su_root_break(app->root);
        break;
    case nua_r_invite:
        if (status == 183 ||
            status == 603)
            su_root_break(app->root);
        break;
    case nua_r_shutdown:
        if (status == 200)
            su_root_break(app->root);
        break;
    default:
        break;
    }
}

void
inv_timeout(struct app *app,
            su_timer_t *timer,
            su_timer_arg_t *timeo)
{
    su_root_break(app->root);
}

static int
invite(const char *user, const char *pass, const char *realm,
       const char *server, const char *dst, int timeo)
{
    su_home_t home;
    struct app *app;
    struct op *inv;
    char uri[256];
    char route[256];
    sip_to_t *from, *to;
    su_timer_t *timer;
    int rc;

    inv = NULL;

    su_init();

    su_home_init(&home);

    app = su_zalloc(&home, sizeof(*app));

    rc = app ? 0 : -1;
    if (rc)
        goto out;

    app->user = user;
    app->pass = pass;
    app->realm = realm;
    app->server = server;
    app->home = &home;
    app->root = su_root_create(app);

    rc = app->root ? 0 : -1;
    if (rc)
        goto out;

    app->nua = nua_create(app->root,
                          inv_event, app,
                          TAG_END());

    rc = app->nua ? 0 : -1;
    if (rc)
        goto out;

    inv = su_zalloc(app->home, sizeof(*inv));

    rc = inv ? 0 : -1;
    if (rc)
        goto out;

    snprintf(uri, sizeof(uri), "sip:%s@%s", user, realm);

    from = sip_from_make(app->home, uri);
    rc = from ? 0 : -1;
    if (rc)
        goto out;

    to = sip_to_make(app->home, dst);
    rc = to ? 0 : -1;
    if (rc)
        goto out;

    snprintf(route, sizeof(route), "sip:%s;lr", server);

    inv->nh = nua_handle(app->nua, inv,
                         SIPTAG_TO(to),
                         SIPTAG_FROM(from),
                         NUTAG_M_USERNAME(user),
                         NUTAG_INITIAL_ROUTE_STR(route),
                         TAG_END());

    rc = inv->nh ? 0 : -1;
    if (rc)
        goto out;

    nua_register(inv->nh,
                 SIPTAG_TO(from),
                 TAG_END());

    su_root_run(app->root);

    notice("REGISTER %d\n", inv->status);

    rc = inv->status == 200 ? 0 : -1;
    if (rc)
        goto out;

    nua_invite(inv->nh,
               SOATAG_USER_SDP_STR("m=audio 5004 RTP/AVP 0 8"),
               TAG_END());

    su_root_run(app->root);

    notice("INVITE %d\n", inv->status);

    rc = inv->status == 183 ? 0 : -1;
    if (rc)
        goto out;

    timer = su_timer_create(su_root_task(app->root), timeo);

    rc = timer ? 0 : -1;
    if (rc)
        goto out;

    rc = su_timer_set(timer, inv_timeout, NULL);
    if (rc)
        goto out;

    su_root_run(app->root);

    su_timer_destroy(timer);
out:
    if (app) {
        nua_shutdown(app->nua);
        su_root_run(app->root);
    }

    if (inv) {
        if (inv->nh)
            nua_handle_destroy(inv->nh);
        su_free(app->home, inv);
    }
    if (app) {
        if (app->nua)
            nua_destroy(app->nua);

        if (app->root)
            su_root_destroy(app->root);

        su_free(&home, app);
    }

    su_home_deinit(&home);
    su_deinit();

    return rc;
}

int
main(int argc, char **argv)
{
    const char *user, *pass, *realm, *server;
    int rc, timeo;

    user = NULL;
    pass = NULL;
    realm = NULL;
    server = NULL;
    timeo = 10000;

    vlog = (struct vlog) {
        .target = STDIO,
        .stdio.stream = stderr,
    };

    do {
        int c;

        c = getopt(argc, argv, "u:p:r:s:o:T:h");
        if (c < 0)
            break;

        switch (c) {
        case 'u':
            user = optarg;
            break;
        case 'p':
            pass = optarg;
            break;
        case 'r':
            realm = optarg;
            break;
        case 's':
            server = optarg;
            break;
        case 'o':
            if (!strcmp(optarg, "none"))
                vlog.target = NONE;
            else if (!strcmp(optarg, "syslog"))
                vlog.target = SYSLOG;
            else {
                vlog.stdio.stream = fopen(optarg, "w");
                rc = vlog.stdio.stream ? 0 : -1;
            }
            if (rc)
                goto out;
            break;
        case 'T':
            timeo = atoi(optarg) * 1000;
            break;
        case 'h':
            rc = 0;
        default:
            goto usage;
        }
    } while (1);

    if (!user || !realm || !server)
        goto usage;

    if (optind >= argc)
        goto usage;

    rc = invite(user, pass, realm, server, argv[optind], timeo);
out:
    return rc ? 1 : 0;
usage:
    fprintf(rc ? stderr : stdout,
            "usage: %s -u <user> [-p <password>] -r <realm> -s <server> <dst>\n",
            basename(argv[0]));
    goto out;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "Linux"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
