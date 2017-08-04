/*
 Copyright (c) 2017 Mats Mattsson

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

#ifndef MM_Entitlement_h
#define MM_Entitlement_h

#import <Foundation/Foundation.h>

// Default to hidden symbols
#pragma GCC visibility push(hidden)

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 A type alias to String for a better Swift API.
	 */
	typedef NSString * MMEntitlementName NS_STRING_ENUM;

	/**
	 @brief Get the entitlements from the code signature
	 in the main executable.
	 
	 It finds code signature in the Mach-O binary that contains
	 the main-function and extracts the entitlements property
	 list.
	 
	 @return A dictionary of entilement names and their values. nil if there
	 was an error.
	 */
	NSDictionary<NSString *, id> * _Nullable MMMainEntitlements(void);

	/**
	 @brief Get an entitlement value the code signature
	 in the main executable.
	 
	 @see MMMainEntitlements
	 
	 @param entitlementName Name of the entitlement.
	 @return The value of the entitlement if it is present. nil if there was an
	 error.
	 */
	id _Nullable MMMainEntitlement(_Nonnull MMEntitlementName entitlementName);

	/**
	 [Mac] Read-write address book.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.personal-information.addressbook"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameAddressBook;

	/**
	 [iPhone] Receive push notifications.

	 Entitlement Key Reference - Enabling Push Notifications

	 @code "aps-environment"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameApplePushServices;

	/**
	 [Mac] Receive push notifications.

	 Entitlement Key Reference - Enabling Push Notifications

	 @code "com.apple.developer.aps-environment"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameApplePushServicesMac;

	/**
	 [Mac, iPhone] Share resources between apps.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.application-groups"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameApplicationGroups;

	/**
	 [iPhone] Application identifier.

	 Technical Q&A QA1710

	 @code "application-identifier"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameApplicationIdentifier;

	/**
	 [Mac] Application identifier.
	 
	 Technical Q&A QA1710

	 @code "com.apple.application-identifier"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameApplicationIdentifierMac;

	/**
	 [Mac] Enable the App sandbox.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.app-sandbox"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameAppSandbox;

	/**
	 [Mac] Child processes inherit sandbox.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.inherit"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameAppSandboxInherit;

	/**
	 [iPhone] Shared Web-credentials, universal links.

	 App Search Programming Guide
	 
	 @code "com.apple.developer.associated-domains"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameAssociatedDomains;

	/**
	 [Mac] Access AVB devices.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.device.audio-video-bridging"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameAudioVideoBridging;

	/**
	 [Mac] Access Bluetooth devices.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.device.bluetooth"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameBluetooth;

	/**
	 [Mac] Read-write calendars.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.personal-information.calendars"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameCalendars;

	/**
	 [Mac] Access the camera.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.device.camera"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameCamera;

	/**
	 [iPhone] The default file protection mode.

	 @code "com.apple.developer.default-data-protection"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameDefaultDataProtection;

	/**
	 [Mac] Read-write access to downloads folder.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.files.downloads.read-write"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameDownloadsReadWrite;

	/**
	 [Mac] Enable file bookmarks for an app.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.files.bookmarks.app-scope"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameFileBookmarkAppScope;

	/**
	 [Mac] Enable file bookmarks for a document.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.files.bookmarks.document-scope"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameFileBookmarkDocumentScope;

	/**
	 [Mac] Execute user selected files.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.files.user-selected.executable"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameFileUserSelectedExecutable;

	/**
	 [Mac] Read user selected files.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.files.user-selected.read-only"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameFileUserSelectedReadOnly;

	/**
	 [Mac] Write to user selected files.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.files.user-selected.read-write"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameFileUserSelectedReadWrite;

	/**
	 [Mac] Access Firewire devices.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.device.firewire"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameFirewire;

	/**
	 [iPhone] Allow debugging.

	 @code "get-task-allow"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameGetTaskAllow;

	/**
	 [iPhone] Access HealthKit.

	 @code "com.apple.developer.healthkit"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameHealthKit;

	/**
	 [iPhone] Access HomeKit.

	 @code "com.apple.developer.homekit"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameHomeKit;


	/**
	 [iPhone] Access Hotspot Configuration.

	 @code "com.apple.developer.networking.HotspotConfiguration"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameHotspotConfiguration;

	/**
	 [Mac, iPhone] iCloud container identifier.

	 iCloud Design Guide

	 @code "com.apple.developer.icloud-container-identifiers"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameICloudContainerIdentifiers;

	/**
	 [Mac, iPhone] iCloud container identifier.

	 iCloud Design Guide
	 
	 @code "com.apple.developer.ubiquity-container-identifiers"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameICloudDocumentStorageIdentifiers;

	/**
	 [Mac, iPhone] iCloud key value storage identifier.

	 iCloud Design Guide
	 Entitlement Key Reference - Enabling iCloud Storage

	 @code "com.apple.developer.ubiquity-kvstore-identifier"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameICloudKeyValueStorageIdentifer;

	/**
	 [Mac, iPhone] iCloud services.

	 iCloud Design Guide

	 @code "com.apple.developer.icloud-services"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameICloudServices;

	/**
	 [Mac, iPhone] In app payments.

	 Entitlement Key Reference - Apple Pay and Passkit Entitlements

	 @code "com.apple.developer.in-app-payments"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameInAppPayments;

	/**
	 [iPhone] Inter app audio.

	 @code "inter-app-audio"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameInterAppAudio;

	/**
	 [iPhone] Keychain access groups.

	 Technical Note TN2415

	 @code "keychain-access-groups"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameKeychainAccessGroups;

	/**
	 [Mac] Access location services.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.personal-information.location"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameLocation;

	/**
	 [Mac] Access microphone.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.device.microphone"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameMicrophone;

	/**
	 [Mac] Read movies library.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.assets.movies.read-only"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameMoviesReadOnly;

	/**
	 [Mac] Read-write movies library.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.assets.movies.read-write"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameMoviesReadWrite;

	/**
	 [Mac] Read music library.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.assets.music.read-only"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameMusicReadOnly;

	/**
	 [Mac] Read-write music library.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.assets.music.read-write"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameMusicReadWrite;

	/**
	 [Mac] Make outgoing network requests.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.network.client"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameNetworkClient;

	/**
	 [iPhone] Network extensions.

	 NetworkExtension framework

	 @code "com.apple.developer.networking.networkextension"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameNetworkExtension;

	/**
	 [iPhone] Network multipath
	 
	 WWDC 2017 - Sesson 707 - Advances in Networking, Part 1
	 WWDC 2017 - Sesson 709 - Advances in Networking, Part 2

	 @code "com.apple.developer.networking.multipath"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameNetworkMultipath;

	/**
	 [Mac] Receive incoming network requests.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.network.server"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameNetworkServer;

	/**
	 [iPhone] Access Personal VPN Api.

	 NetworkExtension framework
	 
	 @code "com.apple.developer.networking.vpn.api"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameNetworkVPNAPI;

	/**
	 [iPhone] Access NFC reading.

	 @code "com.apple.developer.nfc.readersession.formats"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameNFCTagReadingFormats;

	/**
	 [iPhone] Keep app in foreground near NFC readers.

	 Entitlement Key Reference - Apple pay and Passkit Entitlements
	 
	 @code "com.apple.developer.passkit.pass-presentation-suppression"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNamePassPresentationSuppression;

	/**
	 [iPhone] Access Passkit passes.

	 Entitlement Key Reference - Apple pay and Passkit Entitlements

	 @code "com.apple.developer.pass-type-identifiers"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNamePassTypeIdentifiers;

	/**
	 [iPhone] Enable setting up Apple pay.

	 Entitlement Key Reference - Apple pay and Passkit Entitlements
	 
	 @code "com.apple.developer.payment-pass-provisioning"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNamePaymentPassProvisioning;

	/**
	 [Mac] Read photos library.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.assets.pictures.read-only"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNamePicturesReadOnly;

	/**
	 [Mac] Read-write photos library.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.assets.pictures.read-write"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNamePicturesReadWrite;

	/**
	 [Mac] Apple Event targets.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.scripting-targets"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameScriptingTargets;

	/**
	 [Mac] Access serial devices.

	 Entitlement Key Reference - Enabling App Sandbox
	 
	 @code "com.apple.security.device.serial"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameSerial;

	/**
	 [iPhone] Access SiriKit

	 @code "com.apple.developer.siri"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameSiri;

	/**
	 [Mac, iPhone] Team Identifier. Used for app groups.

	 Technical Q&A QA1879

	 @code "com.apple.developer.team-identifier"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTeamIdentifier;

	/**
	 [Mac] Temporary Exception - Use Apple Events

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements

	 @code "com.apple.security.temporary-exception.apple-events"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionAppleEvents;

	/**
	 [Mac] Temporary Exception - Use unsafe audio units

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements
	 
	 @code "com.apple.security.temporary-exception.audio-unit-host"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionAudioUnitHost;

	/**
	 [Mac] Temporary Exception - Use global Mach services

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements

	 @code "com.apple.security.temporary-exception.mach-lookup.global-name"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionGlobalMachServiceLookup;

	/**
	 [Mac] Temporary Exception - Register global Mach services

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements
	 
	 @code "com.apple.security.temporary-exception.mach-register.global-name"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionGlobalMachServiceDynamicRegistration;

	/**
	 [Mac] Temporary Exception - Read any file

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements

	 @code "com.apple.security.temporary-exception.files.absolute-path.read-only"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionFileAnyFolderReadOnly;

	/**
	 [Mac] Temporary Exception - Write to any file

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements
	 
	 @code "com.apple.security.temporary-exception.files.absolute-path.read-write"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionFileAnyFolderReadWrite;

	/**
	 [Mac] Temporary Exception - Read files in home folder

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements

	 @code "com.apple.security.temporary-exception.files.home-relative-path.read-only"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionFileHomeFolderReadOnly;

	/**
	 [Mac] Temporary Exception - Write to files in home folder

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements
	 
	 @code "com.apple.security.temporary-exception.files.home-relative-path.read-write"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionFileHomeFolderReadWrite;

	/**
	 [Mac] Temporary Exception - Subclass IOKitUserClient

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements

	 @code "com.apple.security.temporary-exception.iokit-user-client-class"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionIOKitUserClientClass;

	/**
	 [Mac] Temporary Exception - Read shared preferences.

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements
	 
	 @code "com.apple.security.temporary-exception.shared-preference.read-only"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionSharedPreferencesReadOnly;

	/**
	 [Mac] Temporary Exception - Write shared preferences.

	 Entitlement Key Reference - App Sandbox Temporary Exception Entitlements

	 @code "com.apple.security.temporary-exception.shared-preference.read-write"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameTemporaryExceptionSharedPreferencesReadWrite;

	/**
	 [Mac] Access USB devices.

	 Entitlement Key Reference - Enabling App Sandbox

	 @code "com.apple.security.device.usb"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameUSB NS_SWIFT_NAME(USB);

	/**
	 [iPhone] Wireless Accessory Configuration.

	 @code "com.apple.external-accessory.wireless-configuration"
	 */
	extern _Nonnull const MMEntitlementName MMEntitlementNameWirelessConfiguration;
	

#ifdef __cplusplus
}
#endif

#pragma GCC visibility pop

#endif /* MM_Entitlement_h */
