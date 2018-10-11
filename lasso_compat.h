#ifdef HAVE_LASSO_UTILS_H

#include <lasso/utils.h>

#else  /* HAVE_LASSO_UTILS_H */

#define lasso_assign_string(dest,src)           \
{                                               \
    char *__tmp = g_strdup(src);                \
    lasso_release_string(dest);                 \
    dest = __tmp;                               \
}

#define lasso_release_string(dest)              \
	lasso_release_full(dest, g_free)

#define lasso_release_full(dest, free_function) \
{                                               \
    if (dest) {                                 \
        free_function(dest); dest = NULL;       \
    }                                           \
}

#define lasso_check_type_equality(a,b)

#define lasso_release_full2(dest, free_function, type)  \
{                                                       \
    lasso_check_type_equality(dest, type);              \
    if (dest) {                                         \
        free_function(dest); dest = NULL;               \
    }                                                   \
}

#define lasso_release_list(dest)                        \
	lasso_release_full2(dest, g_list_free, GList*)

#define lasso_release_list_of_full(dest, free_function)         \
{                                                               \
    GList **__tmp = &(dest);                                    \
    if (*__tmp) {                                               \
        g_list_foreach(*__tmp, (GFunc)free_function, NULL);     \
        lasso_release_list(*__tmp);                             \
    }                                                           \
}

#define lasso_release_list_of_strings(dest)     \
	lasso_release_list_of_full(dest, g_free)


#ifndef __LASSO_TOOLS_H__

LASSO_EXPORT char* lasso_build_unique_id(unsigned int size);
LASSO_EXPORT guint lasso_log_set_handler(GLogLevelFlags log_levels, GLogFunc log_func, gpointer user_data);
LASSO_EXPORT void lasso_log_remove_handler(guint handler_id);

#endif  /* __LASSO_TOOLS_H__ */

#endif  /* HAVE_LASSO_UTILS_H */

#ifndef LASSO_SAML2_ECP_PROFILE_WANT_AUTHN_SIGNED
#define LASSO_SAML2_ECP_PROFILE_WANT_AUTHN_SIGNED "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp:2.0:WantAuthnRequestsSigned"
#endif

#ifndef LASSO_SAML2_CONDITIONS_DELEGATION
#define LASSO_SAML2_CONDITIONS_DELEGATION "urn:oasis:names:tc:SAML:2.0:conditions:delegation"
#endif

#ifndef LASSO_SAML_EXT_CHANNEL_BINDING
#define LASSO_SAML_EXT_CHANNEL_BINDING "urn:oasis:names:tc:SAML:protocol:ext:channel-binding"
#endif
