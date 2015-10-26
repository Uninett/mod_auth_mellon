#ifdef HAVE_LASSO_UTILS_H

#include <lasso/utils.h>

#else

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


#endif

#ifndef LASSO_SAML2_ECP_PROFILE_WANT_AUTHN_SIGNED
#define LASSO_SAML2_ECP_PROFILE_WANT_AUTHN_SIGNED "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp:2.0:WantAuthnRequestsSigned"
#endif

#ifndef LASSO_SAML2_CONDITIONS_DELEGATION
#define LASSO_SAML2_CONDITIONS_DELEGATION "urn:oasis:names:tc:SAML:2.0:conditions:delegation"
#endif

#ifndef LASSO_SAML_EXT_CHANNEL_BINDING
#define LASSO_SAML_EXT_CHANNEL_BINDING "urn:oasis:names:tc:SAML:protocol:ext:channel-binding"
#endif
