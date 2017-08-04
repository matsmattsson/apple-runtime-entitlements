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

#include "MMEntitlement.h"

#include <dlfcn.h>
#include <mach-o/loader.h>

#define CODE_SIGNATURE_SUPER_BLOB_MAGIC (0xfade0cc0)
#define CODE_SIGNATURE_ENTITLEMENTS_BLOB_MAGIC (0xfade7171)

/**
 Store offset and size of a range in a buffer.
 */
struct OffsetWithSize_32 {
	uint32_t offset;
	uint32_t size;
};

/**
 Store a pointer to a buffer and the buffer size.
 */
struct ConstPointerWithSize {
	const void *pointer;
	size_t size;
};

const MMEntitlementName MMEntitlementNameAddressBook = @"com.apple.security.personal-information.addressbook";
const MMEntitlementName MMEntitlementNameApplePushServices = @"aps-environment";
const MMEntitlementName MMEntitlementNameApplePushServicesMac = @"com.apple.developer.aps-environment";
const MMEntitlementName MMEntitlementNameApplicationGroups = @"com.apple.security.application-groups";
const MMEntitlementName MMEntitlementNameApplicationIdentifier = @"application-identifier";
const MMEntitlementName MMEntitlementNameApplicationIdentifierMac = @"com.apple.application-identifier";
const MMEntitlementName MMEntitlementNameAppSandbox = @"com.apple.security.app-sandbox";
const MMEntitlementName MMEntitlementNameAppSandboxInherit = @"com.apple.security.inherit";
const MMEntitlementName MMEntitlementNameAssociatedDomains = @"com.apple.developer.associated-domains";
const MMEntitlementName MMEntitlementNameAudioVideoBridging = @"com.apple.security.device.audio-video-bridging";
const MMEntitlementName MMEntitlementNameBluetooth = @"com.apple.security.device.bluetooth";
const MMEntitlementName MMEntitlementNameCalendars = @"com.apple.security.personal-information.calendars";
const MMEntitlementName MMEntitlementNameCamera = @"com.apple.security.device.camera";
const MMEntitlementName MMEntitlementNameDefaultDataProtection = @"com.apple.developer.default-data-protection";
const MMEntitlementName MMEntitlementNameDownloadsReadWrite = @"com.apple.security.files.downloads.read-write";
const MMEntitlementName MMEntitlementNameFileBookmarkAppScope = @"com.apple.security.files.bookmarks.app-scope";
const MMEntitlementName MMEntitlementNameFileBookmarkDocumentScope = @"com.apple.security.files.bookmarks.document-scope";
const MMEntitlementName MMEntitlementNameFileUserSelectedExecutable = @"com.apple.security.files.user-selected.executable";
const MMEntitlementName MMEntitlementNameFileUserSelectedReadOnly = @"com.apple.security.files.user-selected.read-only";
const MMEntitlementName MMEntitlementNameFileUserSelectedReadWrite = @"com.apple.security.files.user-selected.read-write";
const MMEntitlementName MMEntitlementNameFirewire = @"com.apple.security.device.firewire";
const MMEntitlementName MMEntitlementNameGetTaskAllow = @"get-task-allow";
const MMEntitlementName MMEntitlementNameHealthKit = @"com.apple.developer.healthkit";
const MMEntitlementName MMEntitlementNameHomeKit = @"com.apple.developer.homekit";
const MMEntitlementName MMEntitlementNameHotspotConfiguration = @"com.apple.developer.networking.HotspotConfiguration";
const MMEntitlementName MMEntitlementNameICloudContainerIdentifiers = @"com.apple.developer.icloud-container-identifiers";
const MMEntitlementName MMEntitlementNameICloudDocumentStorageIdentifiers = @"com.apple.developer.ubiquity-container-identifiers";
const MMEntitlementName MMEntitlementNameICloudKeyValueStorageIdentifer = @"com.apple.developer.ubiquity-kvstore-identifier";
const MMEntitlementName MMEntitlementNameICloudServices = @"com.apple.developer.icloud-services";
const MMEntitlementName MMEntitlementNameInAppPayments = @"com.apple.developer.in-app-payments";
const MMEntitlementName MMEntitlementNameInterAppAudio = @"inter-app-audio";
const MMEntitlementName MMEntitlementNameKeychainAccessGroups = @"keychain-access-groups";
const MMEntitlementName MMEntitlementNameLocation = @"com.apple.security.personal-information.location";
const MMEntitlementName MMEntitlementNameMicrophone = @"com.apple.security.device.microphone";
const MMEntitlementName MMEntitlementNameMoviesReadOnly = @"com.apple.security.assets.movies.read-only";
const MMEntitlementName MMEntitlementNameMoviesReadWrite = @"com.apple.security.assets.movies.read-write";
const MMEntitlementName MMEntitlementNameMusicReadOnly = @"com.apple.security.assets.music.read-only";
const MMEntitlementName MMEntitlementNameMusicReadWrite = @"com.apple.security.assets.music.read-write";
const MMEntitlementName MMEntitlementNameNetworkClient = @"com.apple.security.network.client";
const MMEntitlementName MMEntitlementNameNetworkExtension = @"com.apple.developer.networking.networkextension";
const MMEntitlementName MMEntitlementNameNetworkMultipath = @"com.apple.developer.networking.multipath";
const MMEntitlementName MMEntitlementNameNetworkServer = @"com.apple.security.network.server";
const MMEntitlementName MMEntitlementNameNetworkVPNAPI = @"com.apple.developer.networking.vpn.api";
const MMEntitlementName MMEntitlementNameNFCTagReadingFormats = @"com.apple.developer.nfc.readersession.formats";
const MMEntitlementName MMEntitlementNamePassPresentationSuppression = @"com.apple.developer.passkit.pass-presentation-suppression";
const MMEntitlementName MMEntitlementNamePassTypeIdentifiers = @"com.apple.developer.pass-type-identifiers";
const MMEntitlementName MMEntitlementNamePaymentPassProvisioning = @"com.apple.developer.payment-pass-provisioning";
const MMEntitlementName MMEntitlementNamePicturesReadOnly = @"com.apple.security.assets.pictures.read-only";
const MMEntitlementName MMEntitlementNamePicturesReadWrite = @"com.apple.security.assets.pictures.read-write";
const MMEntitlementName MMEntitlementNameScriptingTargets = @"com.apple.security.scripting-targets";
const MMEntitlementName MMEntitlementNameSerial = @"com.apple.security.device.serial";
const MMEntitlementName MMEntitlementNameSiri = @"com.apple.developer.siri";
const MMEntitlementName MMEntitlementNameTeamIdentifier = @"com.apple.developer.team-identifier";
const MMEntitlementName MMEntitlementNameTemporaryExceptionAppleEvents = @"com.apple.security.temporary-exception.apple-events";
const MMEntitlementName MMEntitlementNameTemporaryExceptionAudioUnitHost = @"com.apple.security.temporary-exception.audio-unit-host";
const MMEntitlementName MMEntitlementNameTemporaryExceptionGlobalMachServiceLookup = @"com.apple.security.temporary-exception.mach-lookup.global-name";
const MMEntitlementName MMEntitlementNameTemporaryExceptionGlobalMachServiceDynamicRegistration = @"com.apple.security.temporary-exception.mach-register.global-name";
const MMEntitlementName MMEntitlementNameTemporaryExceptionFileAnyFolderReadOnly = @"com.apple.security.temporary-exception.files.absolute-path.read-only";
const MMEntitlementName MMEntitlementNameTemporaryExceptionFileAnyFolderReadWrite = @"com.apple.security.temporary-exception.files.absolute-path.read-write";
const MMEntitlementName MMEntitlementNameTemporaryExceptionFileHomeFolderReadOnly = @"com.apple.security.temporary-exception.files.home-relative-path.read-only";
const MMEntitlementName MMEntitlementNameTemporaryExceptionFileHomeFolderReadWrite = @"com.apple.security.temporary-exception.files.home-relative-path.read-write";
const MMEntitlementName MMEntitlementNameTemporaryExceptionIOKitUserClientClass = @"com.apple.security.temporary-exception.iokit-user-client-class";
const MMEntitlementName MMEntitlementNameTemporaryExceptionSharedPreferencesReadOnly = @"com.apple.security.temporary-exception.shared-preference.read-only";
const MMEntitlementName MMEntitlementNameTemporaryExceptionSharedPreferencesReadWrite = @"com.apple.security.temporary-exception.shared-preference.read-write";
const MMEntitlementName MMEntitlementNameUSB = @"com.apple.security.device.usb";
const MMEntitlementName MMEntitlementNameWirelessConfiguration = @"com.apple.external-accessory.wireless-configuration";


/**
 Create a ConstPointerWithSize.
 @param pointer A memory pointer.
 @param size The size of the buffer.
 @return A ConstPointerWithSize
 */
static struct ConstPointerWithSize ConstPointerWithSizeMake(const void *pointer, const size_t size) {
	struct ConstPointerWithSize pointer_with_size = {
		.pointer = pointer,
		.size = size,
	};
	return pointer_with_size;
}

/**
 Create a ConstPointerWithSize from a pointer and range.
 @param pointer Poiner to a buffer
 @param offset Range of new buffer in old buffer.
 @return A ConstPointerWithSize
 */
static struct ConstPointerWithSize ConstPointerWithSizeMakeWithOffset(const void *pointer, struct OffsetWithSize_32 offset) {
	struct ConstPointerWithSize pointer_with_size = {
		.pointer = (const char *)pointer + offset.offset,
		.size = offset.size,
	};
	return pointer_with_size;
}

/**
 Read a uint32_t from memory, regardless of alignment.
 @return A uint32_t value.
 */
static uint32_t read_uint32(const void * const ptr) {
	uint32_t val;
	memcpy(&val, ptr, sizeof(val));
	return val;
}

/**
 Search for the LC_CODE_SIGNATURE command in a Mach-O load command
 list.
 
 Fails if there the load command is missing, or there exists
 more than one.
 
 @param commands The buffer of load commands.
 @param commands_count The number of load commands.
 @param code_signature_offset_size [out] The offset and size in the
 LC_CODE_SIGNATURE command.
 @return Zero on success.
 */
static int code_signature_offset_in_load_commands(const struct ConstPointerWithSize commands, uint32_t const commands_count, struct OffsetWithSize_32 * const code_signature_offset_size) {
	int result = -1;

	if (commands.pointer && code_signature_offset_size) {
		uint32_t code_signature_command_count = 0;
		struct OffsetWithSize_32 temp = { 0, 0 };
		int has_temp_value = 0;

		for (uint32_t offset = 0, index = 0; index < commands_count && offset < commands.size; ++index) {
			size_t const available_commands_size = commands.size - offset;

			if (available_commands_size < sizeof(struct load_command)) {
				break;
			}

			struct load_command current_command;
			memcpy(&current_command, (const char *)commands.pointer + offset, sizeof(current_command));

			if (available_commands_size < current_command.cmdsize) {
				break;
			}

			if (current_command.cmd == LC_CODE_SIGNATURE) {
				code_signature_command_count += 1;

				if (current_command.cmdsize == sizeof(struct load_command) + 2 * sizeof(uint32_t)) {
					const char *offset_ptr = (const char *)commands.pointer + offset + sizeof(current_command);
					temp.offset = read_uint32(offset_ptr);
					const char *size_ptr = offset_ptr + sizeof(temp.offset);
					temp.size = read_uint32(size_ptr);
					has_temp_value = 1;
				}
			}

			if (UINT32_MAX - offset < current_command.cmdsize) {
				break;
			}
			offset += current_command.cmdsize;
		}

		if (1 == code_signature_command_count && has_temp_value) {
			*code_signature_offset_size = temp;
			result = 0;
		}
	}

	return result;
}

/**
 Search for the LC_CODE_SIGNATURE buffer in a loaded
 Mach-O file.
 
 @param image_ptr Pointer to the start of the Mach-O file.
 @param code_signature [out] The code signature buffer.
 @result Zero on success.
 */
static int code_signature_in_image(void const * const image_ptr, struct ConstPointerWithSize * const code_signature) {
	int result = -1;

	if (image_ptr && code_signature) {
		uint32_t header_magic = read_uint32(image_ptr);

		struct ConstPointerWithSize commands = ConstPointerWithSizeMake(NULL, 0);
		uint32_t number_of_commands = 0;
		int has_commands = 0;

		switch (header_magic) {
			case MH_MAGIC:
				has_commands = 1;
				number_of_commands = read_uint32(image_ptr + 4 * sizeof(uint32_t));
				commands = ConstPointerWithSizeMake(image_ptr + 7 * sizeof(uint32_t), read_uint32(image_ptr + 5 * sizeof(uint32_t)));
				break;
			case MH_CIGAM:
				break;
			case MH_MAGIC_64:
				has_commands = 1;
				number_of_commands = read_uint32(image_ptr + 4 * sizeof(uint32_t));
				commands = ConstPointerWithSizeMake(image_ptr + 8 * sizeof(uint32_t), read_uint32(image_ptr + 5 * sizeof(uint32_t)));
				break;
			case MH_CIGAM_64:
				break;
			default:
				break;
		}

		if (has_commands) {
			struct OffsetWithSize_32 temp_code_signature_offset_size;

			int result_offset = code_signature_offset_in_load_commands(commands, number_of_commands, &temp_code_signature_offset_size);

			if (0 == result_offset) {
				*code_signature = ConstPointerWithSizeMakeWithOffset(image_ptr, temp_code_signature_offset_size);
				result = 0;
			} else {
				result = result_offset;
			}
		}
	}

	return result;
}

/**
 Search for the LC_CODE_SIGNATURE buffer it the Mach-O file for a given loaded
 symbol.

 @param symbol_address Symbol address of the Mach-O file.
 @param code_signature [out] The code signature buffer.
 @result Zero on success.
 */
static int code_signature_for_symbol(void const * const symbol_address, struct ConstPointerWithSize * const code_signature) {
	int result = -1;
	if (symbol_address && code_signature) {
		Dl_info image_info;
		memset(&image_info, 0, sizeof(image_info));

		if (dladdr(symbol_address, &image_info)) {
			if (image_info.dli_fbase) {
				result = code_signature_in_image(image_info.dli_fbase, code_signature);
			}
		}
	}

	return result;
}

/**
 Get the entitlements property list in a code signature.
 
 @param code_signature The code signature.
 @return The entitlements.
 */
static NSDictionary<NSString *, id> *entitlements_in_code_signature(struct ConstPointerWithSize const code_signature) {
	NSDictionary<NSString *, id> *result = nil;
	NSDictionary<NSString *, id> *temp_result = nil;
	int number_of_entitlements_blobs = 0;

	size_t const super_blob_header_size = 3 * sizeof(uint32_t);

	if (code_signature.pointer && code_signature.size >= super_blob_header_size) {
		uint32_t const super_blob_magic = ntohl(read_uint32(code_signature.pointer));
		uint32_t const super_blob_count = ntohl(read_uint32(code_signature.pointer + 2 * sizeof(uint32_t)));

		if (CODE_SIGNATURE_SUPER_BLOB_MAGIC == super_blob_magic) {
			size_t const blob_type_and_offset_size = 2 * sizeof(uint32_t);
			size_t const max_count = (code_signature.size - super_blob_header_size) / blob_type_and_offset_size;
			size_t const blob_count = super_blob_count < max_count ? super_blob_count : max_count;
			const char * const blob_type_and_offset_start = (const char *)code_signature.pointer + super_blob_header_size;

			for (uint32_t index = 0; index < blob_count; ++index) {
				const char *ptr = blob_type_and_offset_start + index * blob_type_and_offset_size;
				uint32_t const blob_offset = ntohl(read_uint32(ptr + sizeof(uint32_t)));

				if (blob_offset <= code_signature.size) {
					size_t const available_size = code_signature.size - blob_offset;

					if (available_size >= 2 * sizeof(uint32_t)) {
						const char * const blob_bytes = (const char *)code_signature.pointer + blob_offset;
						uint32_t const blob_magic = ntohl(read_uint32(blob_bytes));
						uint32_t const blob_length = ntohl(read_uint32(blob_bytes + sizeof(uint32_t)));

						if (blob_length <= available_size && blob_length >= 2 * sizeof(uint32_t)) {
							const char * const blob_content_bytes = blob_bytes + 2 * sizeof(uint32_t);
							const uint32_t blob_content_length = blob_length - 2 * sizeof(uint32_t);

							if (CODE_SIGNATURE_ENTITLEMENTS_BLOB_MAGIC == blob_magic) {
								number_of_entitlements_blobs += 1;

								NSData *blob_data = [[NSData alloc] initWithBytes:blob_content_bytes length:blob_content_length];

								NSError *error = nil;
								NSPropertyListFormat format;

								id<NSObject> plist = [NSPropertyListSerialization propertyListWithData:blob_data options:NSPropertyListImmutable format:&format error:&error];

								if ([plist isKindOfClass:[NSDictionary class]]) {
									temp_result = (NSDictionary *)plist;
								}
							}
						}
					}
				}
			}
		}
	}

	if (1 == number_of_entitlements_blobs) {
		result = temp_result;
	}

	return result;
}

NSDictionary<NSString *, id> * _Nullable MMMainEntitlements(void) {
	void *main_address = dlsym(RTLD_MAIN_ONLY, "main");


	if (!main_address) {
		main_address = dlsym(RTLD_DEFAULT, "main");
	}

	struct ConstPointerWithSize code_signature;

	if (0 == code_signature_for_symbol(main_address, &code_signature)) {
		return entitlements_in_code_signature(code_signature);
	}

	return nil;
}

id _Nullable MMMainEntitlement(_Nonnull MMEntitlementName entitlementName) {
	return [MMMainEntitlements() objectForKey:entitlementName];
}
