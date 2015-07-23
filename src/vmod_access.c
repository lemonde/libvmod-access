#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>

#include "vrt.h"
#include "cache/cache.h"

#include "vcc_if.h"

#include <mhash.h>

struct vsl_log *vsl;
#define VMOD_ACCESS_LOG(...) VSLb(vsl, SLT_Debug, __VA_ARGS__);

#define DEBUG 1

#if defined DEBUG && DEBUG == 1
#define VMOD_ACCESS_DEBUG(...) syslog(LOG_DEBUG, __VA_ARGS__);
#else
#define VMOD_ACCESS_DEBUG(...) ;
#endif

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

VCL_BOOL
vmod_check(const struct vrt_ctx *ctx, VCL_STRING service, VCL_STRING cookie_name, VCL_STRING salt)
{
		const struct gethdr_s cookies_header_struct = { HDR_REQ, "\07Cookie:" };
        char *cookies_header, *cookies_header_dup;
        char **cookies_ptrptr;

        char *current_cookie, **cookie_ptrptr;
        char *current_cookie_name = NULL, *current_cookie_value = NULL, **current_cookie_value_ptrptr = NULL;

        char *version, *services, *services_dup, *user_id, *checksum;
        char checksum_input[8192], checksum_output[32];

        unsigned char *hash;
        MHASH mhash_struct;
        int i;

        char **services_ptrptr, **services_name_date_ptrptr;
        char *services_name, *services_date, *services_name_date;

        time_t service_date_timestamp;

		VMOD_ACCESS_DEBUG("vmod_access: entering access.check()");

        if (!service || !cookie_name || !salt)
        {
            VMOD_ACCESS_LOG("vmod_access: invalid call to access.check()");
            return false;
            // should return a 500
        }

        cookies_header = VRT_GetHdr(ctx, &cookies_header_struct);
        if (cookies_header != NULL)
        {
            // Got some covokies in request, try to find ours
            cookies_header_dup = (char *) WS_Alloc(ctx->ws, strlen(cookies_header));
            strncpy(cookies_header_dup, cookies_header, strlen(cookies_header));
            VMOD_ACCESS_DEBUG("vmod_access: cookies header = '%s'", cookies_header);

            cookies_ptrptr = (char**) WS_Alloc(ctx->ws, sizeof(char*));
            for (current_cookie = strtok_r(cookies_header_dup, "; ", cookies_ptrptr);
                 current_cookie != NULL;
                 current_cookie = strtok_r(NULL, "; ", cookies_ptrptr))
            {
                 // Extract cookie name and value
                cookie_ptrptr = (char**) WS_Alloc(ctx->ws, sizeof(char*));
            	current_cookie_name = strtok_r(current_cookie, "=", cookie_ptrptr);
            	current_cookie_value = strtok_r(NULL, "=", cookie_ptrptr);

                if (strncmp(current_cookie_name, cookie_name, strlen(cookie_name)) == 0)
                {
                    // Found our cookie, extract fields
                	VMOD_ACCESS_DEBUG("vmod_access: got cookie '%s' = '%s', matches", current_cookie_name, current_cookie_value);

                    if (current_cookie_value != NULL)
                    {
                        current_cookie_value_ptrptr = (char**) WS_Alloc(ctx->ws, sizeof(char*));
                        version	= strtok_r(current_cookie_value, "-", current_cookie_value_ptrptr);
                        if (!version)
                        {
                            VMOD_ACCESS_DEBUG("vmod_access: can't extract version in '%s'!", current_cookie_value);
                            continue;
                        }

                        services = strtok_r(NULL, "-", current_cookie_value_ptrptr);
                        if (!services)
                        {
                            VMOD_ACCESS_DEBUG("vmod_access: can't extract services in '%s'!", current_cookie_value);
                            continue;
                        }

                        user_id	= strtok_r(NULL, "-", current_cookie_value_ptrptr);
                        if (!user_id)
                        {
                            VMOD_ACCESS_DEBUG("vmod_access: can't extract user_id in '%s'!", current_cookie_value);
                            continue;
                        }

                        checksum = strtok_r(NULL, "-", current_cookie_value_ptrptr);
                        if (!checksum)
                        {
                            VMOD_ACCESS_DEBUG("vmod_access: can't extract checksum in '%s'!", current_cookie_value);
                            continue;
                        }

                        // Got all fields in cookie
                        VMOD_ACCESS_DEBUG("vmod_access: found version '%s', services '%s', user_id '%s', checksum '%s'", version, services, user_id, checksum);

                        // Extract all (service, date)
                        services_ptrptr = (char**) WS_Alloc(ctx->ws, sizeof(char*));
                        services_dup = (char*) WS_Alloc(ctx->ws, strlen(services));
                        strncpy(services_dup, services, strlen(services));
					    for (services_name_date = strtok_r(services_dup, "~", services_ptrptr);
							 services_name_date != NULL;
							 services_name_date = strtok_r(NULL, "~", services_ptrptr))
					    {
						    services_name_date_ptrptr = (char**) WS_Alloc(ctx->ws, sizeof(char*));
						    services_name = strtok_r(services_name_date, ":", services_name_date_ptrptr);
						    services_date = strtok_r(NULL, ":", services_name_date_ptrptr);

                            // Search for a matching service name
                            VMOD_ACCESS_DEBUG("vmod_access: name = '%s', date = '%s'", services_name, services_date);
                            if (!services_name || !services_date)
                            {
                                continue;
                            }

							// Compare substrings as service "foo" in cookie must match service "foo_YYYYMMDD" in access.check()
                            if (strstr(service, services_name))
                            {
                                // Service name found, check date is still valid
                                VMOD_ACCESS_DEBUG("vmod_access: cookie service name '%s' matches '%s'", services_name, service);
                                errno=0;
                                service_date_timestamp = (time_t)strtol(services_date, NULL, 10);
                                if (errno != 0)
                                {
                                    VMOD_ACCESS_DEBUG("vmod_access: invalid date '%s'", services_date);
                                    continue;
                                }

                                // Check that date is not in the past
                                if(service_date_timestamp >= time(NULL))
                                {
                                    // Found the right service name with a valid date, compare checksum
                                    sprintf(checksum_input, "%s%s%s%s", salt, version, services, user_id);
                                    VMOD_ACCESS_DEBUG("vmod_access: valid date, compute checksum for '%s'", checksum_input);

                                    mhash_struct = mhash_init(MHASH_MD5);
                                    if (mhash_struct == MHASH_FAILED)
                                    {
                                        VMOD_ACCESS_DEBUG("vmod_access: couldn't compute hash");
                                        return false;
                                        // should return 503
                                    }
                                    mhash(mhash_struct, checksum_input, strlen(checksum_input));
                                    hash = mhash_end(mhash_struct);
                                    for (i = 0; i < mhash_get_block_size(MHASH_MD5); i++)
                                    {
                                        sprintf(checksum_output + i*2, "%02x", hash[i]);
                                    }

                                    // Grand access if computed checksum and checksum in cookie match
                                    if (strncmp(checksum_output, checksum, strlen(checksum_output)) == 0)
                                    {
                                        VMOD_ACCESS_DEBUG("vmod_access: computed checksum '%s' matches cookie '%s', access granted!", checksum_output, checksum);
                                        return true;
                                    }
                                    else
                                    {
                                        VMOD_ACCESS_DEBUG("vmod_access: computed checksum '%s' doesn't match cookie '%s'", checksum_output, checksum);
                                    }
                                }
                                else
                                {
                                    VMOD_ACCESS_DEBUG("vmod_access: date '%s' in past", services_date);
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            VMOD_ACCESS_DEBUG("vmod_access: no cookies sent with request");
        }

        VMOD_ACCESS_DEBUG("vmod_access: access denied, leaving acces.check()");
        return false;

}