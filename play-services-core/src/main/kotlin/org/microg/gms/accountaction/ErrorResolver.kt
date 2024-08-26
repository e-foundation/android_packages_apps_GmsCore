package org.microg.gms.accountaction

import android.accounts.Account
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import kotlinx.coroutines.runBlocking
import org.microg.gms.common.Constants
import org.microg.gms.cryptauth.isLockscreenConfigured
import org.microg.gms.cryptauth.sendDeviceScreenlockState
import org.microg.gms.gcm.GcmDatabase
import org.microg.gms.gcm.GcmPrefs
import org.microg.gms.settings.SettingsContract


/**
 * High-level resolution: tell server that user has configured a lock screen
 */
const val DEVICE_MANAGEMENT_SCREENLOCK_REQUIRED = "DeviceManagementScreenlockRequired"

/**
 * Indicates that the user is using an enterprise account that is set up to use Advanced
 * device management features, for which it is required to install a device manager.
 * This is not supported by microG.
 */
const val DEVICE_MANAGEMENT_REQUIRED = "DeviceManagementRequired"

/**
 * Indicates that the user is using an enterprise account that is set up to use Advanced
 * device management features, for which it is required to install a device manager,
 * and that the device also needs manual admin approval.
 * This is not supported by microG.
 */
const val DEVICE_MANAGEMENT_ADMIN_PENDING_APPROVAL = "DeviceManagementAdminPendingApproval"

/**
 * Indicates that the token stored on the device is no longer valid.
 */
const val BAD_AUTHENTICATION = "BadAuthentication"

const val TAG = "GmsAccountErrorResolve"

/**
 * @return `null` if it is unknown how to resolve the problem, an
 * appropriate `Resolution` otherwise
 */
fun Context.resolveAuthErrorMessage(s: String): Resolution? = if (s.startsWith("Error=")) {
    resolveAuthErrorMessage(s.drop("Error=".length))
} else when (s) {
    DEVICE_MANAGEMENT_SCREENLOCK_REQUIRED -> listOf(
        Requirement.ENABLE_CHECKIN,
        Requirement.ENABLE_GCM,
        Requirement.ALLOW_MICROG_GCM,
        Requirement.ENABLE_LOCKSCREEN
    )
        .associateWith { checkRequirementSatisfied(it) }
        .filterValues { satisfied -> !satisfied }.let {
            if (it.isEmpty()) {
                // all requirements are satisfied, crypt auth sync keys can be run
                CryptAuthSyncKeys
            } else {
                // prompt user to satisfy missing requirements
                UserSatisfyRequirements(it.keys)
            }
        }

    DEVICE_MANAGEMENT_ADMIN_PENDING_APPROVAL, DEVICE_MANAGEMENT_REQUIRED ->
        NoResolution(NoResolutionReason.ADVANCED_DEVICE_MANAGEMENT_NOT_SUPPORTED)

    BAD_AUTHENTICATION -> Reauthenticate

    else -> null
}.also { Log.d(TAG, "Error was: $s. Diagnosis: $it.") }

fun Context.checkRequirementSatisfied(requirement: Requirement): Boolean = when (requirement) {
    Requirement.ENABLE_CHECKIN -> isCheckinEnabled()
    Requirement.ENABLE_GCM -> isGcmEnabled()
    Requirement.ALLOW_MICROG_GCM -> isMicrogAppGcmAllowed()
    Requirement.ENABLE_LOCKSCREEN -> isLockscreenConfigured()
}

fun Context.isCheckinEnabled(): Boolean {
    val settingsProjection = arrayOf(
        SettingsContract.CheckIn.ENABLED,
        SettingsContract.CheckIn.LAST_CHECK_IN
    )
    return SettingsContract.getSettings(this, SettingsContract.CheckIn.getContentUri(this), settingsProjection) { cursor ->
        val checkInEnabled = cursor.getInt(0) != 0
        val lastCheckIn = cursor.getLong(1)

        // user is also asked to enable checkin if there had never been a successful checkin (network errors?)
        lastCheckIn > 0 && checkInEnabled
    }
}

fun Context.isGcmEnabled(): Boolean = GcmPrefs.get(this).isEnabled

fun Context.isMicrogAppGcmAllowed(): Boolean {
    val gcmPrefs = GcmPrefs.get(this)
    val gcmDatabaseEntry = GcmDatabase(this).use {
        it.getApp(Constants.GMS_PACKAGE_NAME)
    }
    return !(gcmDatabaseEntry != null &&
            !gcmDatabaseEntry.allowRegister ||
            gcmDatabaseEntry == null &&
            gcmPrefs.confirmNewApps)

}

fun <T> Resolution.resolveToActionOrResult(context: Context, account: Account, retryFunction: () -> T): Either<Intent, T> {
    when (this) {
        CryptAuthSyncKeys -> {
            Log.d(TAG, "Resolving account error by performing cryptauth sync keys call.")
            runBlocking {
                context.sendDeviceScreenlockState(account)
            }
            return Either.Right(retryFunction())
        }
        is NoResolution -> {
            Log.w(TAG, "This account cannot be used with microG due to $reason")
            return Either.Left(TODO())
        }
        is UserSatisfyRequirements -> {
            Log.w(TAG, "User intervention required! You need to ${actions.joinToString(", ")}.")
            return Either.Left(AccountActionActivity.createIntent(context, account, this))
        }
        Reauthenticate -> {
            Log.w(TAG, "Your account credentials have expired! Please remove the account, then sign in again.")
            return Either.Left(TODO())
        }
    }
}

fun <T> Resolution.initiateFromForegroundBlocking(context: Context, account: Account, retryFunction: () -> T): T? {
    val actionOrResolution = resolveToActionOrResult(context, account, retryFunction)
    return when (actionOrResolution) {
        is Either.Left -> {
            context.startActivity(actionOrResolution.left)
            null
        }
        is Either.Right -> actionOrResolution.right
    }
}

sealed class Either<out L, out R> {
    data class Left<out L>(val left: L) : Either<L, Nothing>()
    data class Right<out R>(val right: R) : Either<Nothing, R>()
}