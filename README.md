# MMEntitlement

Apple only enables some functionality for an executable if it has been signed with a specific entitlement.
This is utility function to get the entitlements from within a signed executable at run time.

It does the same as the following `codesign` command:

    $ codesign -d --entitlements :- path/to/signed/Executable

The entitlements are mostly known at build time, so a build time check is preferred instead of this code.

## Example code

Check if the app may be debugged on an iPhone:

    if let debuggable = MMMainEntitlement(.getTaskAllow) as? Bool, debuggable {
        print("Debuggable")
    }

## Installation

Download the files and add them to your project and add `MMEntitlements.h` to the bridging header. 
