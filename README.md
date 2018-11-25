# azure-csharp-rbac-role-assignment

Demonstration of how to assign a role to a principal on a resource scope using an Azure Function (C#) and ARM template. Use of ARM template role assignments is preferred, but this repo demonstrates how you can programmatically assign a role. Some example use cases include when:

- You don't know all the principal Ids in advance
- The application that deploys ARM templates has elevated permissions that you must exploit to gather information for role assignment.
