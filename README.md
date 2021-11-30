# Simple PBKDF2

This is an easy to understand PBKDF2 implementation written in C#.
It's intended for people that want to understand the algorithm

## Use in security critical applications

This implementation will generate output that exactly conforms to the standard
and is compatible with commercially used PBKDF2 implementations.

Because of the managed nature of the code, it's easy to audit.

### Speed

This implementation is not made to be fast but easy to understand.
Because of this, you will experience sub-par performance.

To get better performance, you can use `System.Security.Cryptography.Rfc2898DeriveBytes` instead.

Note: For Rfc2898DeriveBytes to actually be fast,
you may need to to uncheck "Prefer 32 bits" in the project properties.
Alternatively, you can use an unmanaged solution on Windows.

Details: https://cable.ayra.ch/md/pbkdf2-in-dotnet

The end of this article has an implementation for the Windows crypto API.
