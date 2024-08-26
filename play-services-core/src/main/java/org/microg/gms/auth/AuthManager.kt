/*
 * SPDX-FileCopyrightText: 2023 microG Project Team
 * SPDX-License-Identifier: Apache-2.0
 */
package org.microg.gms.auth

import android.accounts.Account
import android.accounts.AccountManager
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import org.microg.gms.accountaction.initiateFromBackgroundBlocking
import org.microg.gms.accountaction.initiateFromForegroundBlocking
import org.microg.gms.accountaction.resolveAuthErrorMessage
import org.microg.gms.auth.AuthPrefs.isTrustGooglePermitted
import org.microg.gms.common.NotOkayException
import org.microg.gms.common.PackageUtils
import org.microg.gms.settings.SettingsContract
import java.io.IOException

class AuthManager(
    private val context: Context,
    private val accountName: String,
    private val packageName: String?,
    @JvmField val service: String
) {
    var dynamicFields: MutableMap<Any, Any> = HashMap()
    private var accountManager: AccountManager? = null
    private var account: Account? = null
    var packageSignature: String? = null
        get() {
            if (field == null) field = PackageUtils.firstSignatureDigest(context, packageName)
            return field
        }
    private var accountType: String? = null

    private var delegationType = 0
    private var delegateeUserId: String? = null
    private var oauth2Foreground: String? = null
    private var oauth2Prompt: String? = null
    private var itCaveatTypes: String? = null
    private var tokenRequestOptions: String? = null
    var includeEmail: String? = null
    var includeProfile: String? = null
    var isGmsApp: Boolean = false
    var ignoreStoredPermission: Boolean = false

    fun getAccountType(): String {
        if (accountType == null) accountType = AuthConstants.DEFAULT_ACCOUNT_TYPE
        return accountType!!
    }

    fun getAccountManager(): AccountManager? {
        if (accountManager == null) accountManager = AccountManager.get(context)
        return accountManager
    }

    fun getAccount(): Account {
        if (account == null) account = Account(accountName, getAccountType())
        return account!!
    }

    @JvmOverloads
    fun buildTokenKey(service: String = this.service): String {
        val builder = Uri.EMPTY.buildUpon()
        if (delegationType != 0 && delegateeUserId != null) builder.appendQueryParameter(
            "delegation_type",
            delegationType.toString()
        )
            .appendQueryParameter("delegatee_user_id", delegateeUserId)
        if (tokenRequestOptions != null) builder.appendQueryParameter(
            "token_request_options",
            tokenRequestOptions
        )
        if (includeEmail != null) builder.appendQueryParameter("include_email", includeEmail)
        if (includeProfile != null) builder.appendQueryParameter("include_profile", includeEmail)
        val query = builder.build().encodedQuery
        return packageName + ":" + packageSignature + ":" + service + (if (query != null) ("?$query") else "")
    }

    fun buildPermKey(): String {
        return "perm." + buildTokenKey()
    }

    var isPermitted: Boolean
        get() {
            if (!service.startsWith("oauth")) {
                if (context.packageManager.checkPermission(
                        PERMISSION_TREE_BASE + service,
                        packageName!!
                    ) == PackageManager.PERMISSION_GRANTED
                ) {
                    return true
                }
            }
            val perm = getUserData(buildPermKey())
            if ("1" != perm) {
                return false
            }
            return true
        }
        set(value) {
            setUserData(buildPermKey(), if (value) "1" else "0")
            if (Build.VERSION.SDK_INT >= 26 && value && packageName != null) {
                // Make account persistently visible as we already granted access
                accountManager!!.setAccountVisibility(
                    getAccount(),
                    packageName,
                    AccountManager.VISIBILITY_VISIBLE
                )
            }
        }

    fun getUserData(key: String?): String? {
        return getAccountManager()!!.getUserData(getAccount(), key)
    }

    fun setUserData(key: String?, value: String?) {
        getAccountManager()!!.setUserData(getAccount(), key, value)
    }

    fun setDelegation(delegationType: Int, delegateeUserId: String?) {
        if (delegationType != 0 && delegateeUserId != null) {
            this.delegationType = delegationType
            this.delegateeUserId = delegateeUserId
        } else {
            this.delegationType = 0
            this.delegateeUserId = null
        }
    }

    fun setOauth2Foreground(oauth2Foreground: String?) {
        this.oauth2Foreground = oauth2Foreground
    }

    fun setOauth2Prompt(oauth2Prompt: String?) {
        this.oauth2Prompt = oauth2Prompt
    }

    fun setItCaveatTypes(itCaveatTypes: String?) {
        this.itCaveatTypes = itCaveatTypes
    }

    fun setTokenRequestOptions(tokenRequestOptions: String?) {
        this.tokenRequestOptions = tokenRequestOptions
    }

    fun putDynamicFiled(key: Any, value: Any) {
        dynamicFields[key] = value
    }

    fun accountExists(): Boolean {
        for (refAccount in getAccountManager()!!.getAccountsByType(accountType)) {
            if (refAccount.name.equals(accountName, ignoreCase = true)) return true
        }
        return false
    }

    fun peekAuthToken(): String {
        Log.d(TAG, "peekAuthToken: " + buildTokenKey())
        return getAccountManager()!!.peekAuthToken(getAccount(), buildTokenKey())
    }

    var authToken: String?
        get() {
            if (service.startsWith("weblogin:")) return null
            if (System.currentTimeMillis() / 1000L >= expiry?.minus(300L) ?: return null) {
                Log.d(TAG, "token present, but expired")
                return null
            }
            return peekAuthToken()
        }
        set(auth) {
            setAuthToken(service, auth)
        }

    fun buildExpireKey(): String {
        return "EXP." + buildTokenKey()
    }

    var expiry: Long?
        get() {
            val exp = getUserData(buildExpireKey())
            return exp?.toLong()
        }
        set(expiry) {
            setUserData(buildExpireKey(), expiry.toString())
        }

    fun setAuthToken(service: String, auth: String?) {
        getAccountManager()!!.setAuthToken(getAccount(), buildTokenKey(service), auth)
        if (Build.VERSION.SDK_INT >= 26 && packageName != null && auth != null) {
            // Make account persistently visible as we already granted access
            accountManager!!.setAccountVisibility(
                getAccount(),
                packageName,
                AccountManager.VISIBILITY_VISIBLE
            )
        }
    }

    fun invalidateAuthToken() {
        val authToken = peekAuthToken()
        invalidateAuthToken(authToken)
    }

    @SuppressLint("MissingPermission")
    fun invalidateAuthToken(auth: String?) {
        getAccountManager()!!.invalidateAuthToken(accountType, auth)
    }

    fun storeResponse(response: AuthResponse) {
        if (service.startsWith("weblogin:")) return
        if (response.accountId != null) setUserData("GoogleUserId", response.accountId)
        if (response.Sid != null) setAuthToken("SID", response.Sid)
        if (response.LSid != null) setAuthToken("LSID", response.LSid)
        if (response.auth != null && (response.expiry != 0L || response.storeConsentRemotely)) {
            authToken = response.auth
            if (response.expiry > 0) {
                expiry = response.expiry
            } else {
                expiry =
                    System.currentTimeMillis() / 1000 + ONE_HOUR_IN_SECONDS // make valid for one hour by default
            }
        }
    }

    private val isSystemApp: Boolean
        get() {
            try {
                val flags = context.packageManager.getApplicationInfo(packageName!!, 0).flags
                return (flags and ApplicationInfo.FLAG_SYSTEM) > 0 || (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) > 0
            } catch (e: PackageManager.NameNotFoundException) {
                return false
            }
        }

    @Throws(IOException::class)
    fun requestAuthWithBackgroundResolution(legacy: Boolean): AuthResponse? {
        return try {
            requestAuth(legacy)
        } catch (e: NotOkayException) {
            if (e.message != null) {
                val errorResolution = context.resolveAuthErrorMessage(
                    e.message!!
                )
                if (errorResolution != null) {
                    errorResolution
                        .initiateFromBackgroundBlocking(
                            context,
                            getAccount()
                        )  // infinite loop is prevented
                        { requestAuth(legacy) }
                } else {
                    throw IOException(e)
                }
            } else {
                throw IOException(e)
            }
        }
    }

    @Throws(IOException::class)
    fun requestAuthWithForegroundResolution(legacy: Boolean): AuthResponse? {
        return try {
            requestAuth(legacy)
        } catch (e: NotOkayException) {
            if (e.message != null) {
                val errorResolution = context.resolveAuthErrorMessage(
                    e.message!!
                )
                if (errorResolution != null) {
                    errorResolution
                        .initiateFromForegroundBlocking(
                            context,
                            getAccount()
                        )  // infinite loop is prevented
                        { requestAuth(legacy) }
                } else {
                    throw IOException(e)
                }
            } else {
                throw IOException(e)
            }
        }
    }

    @Throws(IOException::class)
    fun requestAuth(legacy: Boolean): AuthResponse {
        if (service == AuthConstants.SCOPE_GET_ACCOUNT_ID) {
            val response = AuthResponse()
            response.auth = getAccountManager()!!.getUserData(getAccount(), "GoogleUserId")
            response.accountId = response.auth
            return response
        }
        if (isPermitted || isTrustGooglePermitted(context)) {
            val token = authToken
            if (token != null) {
                val response = AuthResponse()
                response.issueAdvice = "stored"
                response.auth = token
                if (service.startsWith("oauth2:")) {
                    response.grantedScopes = service.substring(7)
                }
                response.expiry = expiry ?: -1
                return response
            }
        }
        val request = AuthRequest().fromContext(context)
            .source("android")
            .app(packageName, packageSignature)
            .email(accountName)
            .token(getAccountManager()!!.getPassword(account))
            .service(service)
            .delegation(delegationType, delegateeUserId)
            .oauth2Foreground(oauth2Foreground)
            .oauth2Prompt(oauth2Prompt)
            .oauth2IncludeProfile(includeProfile)
            .oauth2IncludeEmail(includeEmail)
            .itCaveatTypes(itCaveatTypes)
            .tokenRequestOptions(tokenRequestOptions)
            .systemPartition(isSystemApp)
            .hasPermission(!ignoreStoredPermission && isPermitted)
            .putDynamicFiledMap(dynamicFields)
        if (isGmsApp) {
            request.appIsGms()
        }
        if (legacy) {
            request.callerIsGms().calledFromAccountManager()
        } else {
            request.callerIsApp()
        }
        val response = request.response
        if (!isPermitted && !isTrustGooglePermitted(context)) {
            response.auth = null
        } else {
            storeResponse(response)
        }
        return response
    }

    companion object {
        private const val TAG = "GmsAuthManager"
        const val PERMISSION_TREE_BASE: String =
            "com.google.android.googleapps.permission.GOOGLE_AUTH."
        const val PREF_AUTH_VISIBLE: String = SettingsContract.Auth.VISIBLE
        const val ONE_HOUR_IN_SECONDS: Int = 60 * 60
    }
}
