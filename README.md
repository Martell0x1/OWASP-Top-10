# OWASP Top 10: Mastering Web Security

---
Welcome to the **OWASP Top 10** repository! 🌐💡 This project is a deep dive into the top 10 most critical web application security risks, curated by OWASP—the industry leader in secure software development standards. Whether you're a seasoned developer or just starting your cybersecurity journey, this repo will guide you through each vulnerability, how it works, and, most importantly, how to defend against it.

![OWASP Logo](https://microhackers.net/wp-content/uploads/2021/09/owasp-logo.png)

🔒 **Stay ahead of threats and build more secure applications!**

---
---
# Content
[A01-Acess Control](#a01--2021-broken-acess-control----------------a-05-2017)
---

# Authentication.
- confirms thaat the user who say they are (eta meen?)

# session managment
- a way to identify which subseequent HTTP requrests are beign made by each user (ya3ne lama azoor authenticated pages (edit profile) instead of entring the password and username on each page , we use session managment)

# access control
- determine wether the user is allowed to do the action they intened to do (authorization)

# A01--2021-Broken Acess Control <--------------> (A-05-2017)
- Access control is the application of constraints on who or what is authorized to perform actions or access resources. In the context of web applications, access control is dependent on authentication and session management: 
        - Authentication confirms that the user is who they say they are.
        - Session management identifies which subsequent HTTP requests are being made by that same user.
        - Access control determines whether the user is allowed to carry out the action that they are attempting to perform.

    - Broken access controls are common and often present a critical security vulnerability. Design and management of access controls is a complex and dynamic problem that applies business, organizational, and legal constraints to a technical implementation. Access control design decisions have to be made by humans so the potential for errors is high. 

    ![text](https://portswigger.net/web-security/images/access-control.svg)

    ## Acess Control Security Modules.
    - An access control security model is a formally defined definition of a set of access control rules that is independent of technology or implementation platform. Access control security models are implemented within operating systems, networks, database management systems and back office, application and web server software. Various access control security models have been devised over the years to match access control policies to business or organizational rules and changes in technology. 

    1. Programmatic access control
        - With programmatic access control, a matrix of user privileges is stored in a database or similar and access controls are applied programmatically with reference to this matrix. This approach to access control can include roles or groups or individual users, collections or workflows of processes and can be highly granular.

        - Programmatic access control refers to the ability to manage and enforce permissions and access rights within software applications through code rather than manual configuration. This approach allows for dynamic control over user access based on various factors, such as user roles, attributes, and specific conditions.

        ```
            class User:
                def __init__(self, username, role):
                    self.username = username
                    self.role = role

            class AccessControl:
                def __init__(self):
                    # Define permissions for each role
                    self.permissions = {
                        "Admin": ["create", "read", "update", "delete"],
                        "Editor": ["create", "read", "update"],
                        "Viewer": ["read"]
                    }

                def check_permission(self, user, action):
                    if action in self.permissions.get(user.role, []):
                        return True
                    return False

            # Example usage
            if __name__ == "__main__":
                # Create users with different roles
                admin_user = User("Alice", "Admin")
                editor_user = User("Bob", "Editor")
                viewer_user = User("Charlie", "Viewer")

                access_control = AccessControl()

                # Check permissions for each user
                actions = ["create", "read", "update", "delete"]

                for action in actions:
                    for user in [admin_user, editor_user, viewer_user]:
                        if access_control.check_permission(user, action):
                            print(f"{user.username} (Role: {user.role}) can {action}.")
                        else:
                            print(f"{user.username} (Role: {user.role}) cannot {action}.")

        ```

    2. Discretionary access control (DAC) 
        - With discretionary access control, access to resources or functions is constrained based upon users or named groups of users. Owners of resources or functions have the ability to assign or delegate access permissions to users. This model is highly granular with access rights defined to an individual resource or function and user. Consequently the model can become very complex to design and manage. 

        - Discretionary Access Control (DAC) is a type of access control mechanism where the owner of a resource (like files or data) has the discretion to grant or revoke access rights to other users. In DAC, permissions are typically based on user identity and ownership, allowing users to control access to their own resources.

        ```
        class User:
            def __init__(self, username):
                self.username = username
                self.permissions = {}

        class File:
            def __init__(self, filename, owner):
                self.filename = filename
                self.owner = owner
                self.content = ""
                self.permissions = {"read": set(), "write": set()}

            def write(self, user, data):
                if user.username == self.owner or user.username in self.permissions["write"]:
                    self.content += data
                    print(f"{user.username} wrote to {self.filename}: {data}")
                else:
                    print(f"{user.username} does not have write permission for {self.filename}.")

            def read(self, user):
                if user.username == self.owner or user.username in self.permissions["read"]:
                    print(f"{user.username} read from {self.filename}: {self.content}")
                else:
                    print(f"{user.username} does not have read permission for {self.filename}.")

            def grant_permission(self, user, permission):
                if permission in self.permissions:
                    self.permissions[permission].add(user.username)
                    print(f"{self.owner} granted {permission} permission to {user.username} for {self.filename}.")
                else:
                    print("Invalid permission.")

        # Example usage
        if __name__ == "__main__":
            # Create users
            alice = User("Alice")
            bob = User("Bob")
            charlie = User("Charlie")

            # Alice creates a file
            file1 = File("example.txt", alice.username)

            # Alice grants Bob read and write permissions
            file1.grant_permission(bob, "read")
            file1.grant_permission(bob, "write")

            # Bob tries to write to the file
            file1.write(bob, "Hello, World!")

            # Charlie tries to read the file (should fail)
            file1.read(charlie)

            # Bob reads the file
            file1.read(bob)

            # Charlie tries to write to the file (should fail)
            file1.write(charlie, "This will not work.")

        ```
        - output:
        ```
            Alice granted read permission to Bob for example.txt.
            Alice granted write permission to Bob for example.txt.
            Bob wrote to example.txt: Hello, World!
            Charlie does not have read permission for example.txt.
            Bob read from example.txt: Hello, World!
            Charlie does not have write permission for example.txt.

        ```
    3. Mandatory access control (MAC)
    -  Mandatory access control is a centrally controlled system of access control in which access to some object (a file or other resource) by a subject is constrained. Significantly, unlike DAC the users and owners of resources have no capability to delegate or modify access rights for their resources. This model is often associated with military clearance-based systems.

    - Scenario: Hospital Medical Records System
        Imagine a hospital where access to patient medical records is crucial for maintaining privacy and confidentiality. The hospital uses MAC to control access to these records based on security classifications.
        Definitions:

            Security Classifications:
                Top Secret: Records that contain highly sensitive information (e.g., mental health records).
                Secret: Standard medical records (e.g., surgical history).
                Confidential: Basic information (e.g., allergy information).

            User Roles and Clearances:
                Doctor (Clearance: Top Secret): Can access all records.
                Nurse (Clearance: Secret): Can access standard medical records and below.
                Receptionist (Clearance: Confidential): Can only access basic information.
        
        - code:
            ```
                class User:
                    def __init__(self, username, clearance_level):
                        self.username = username
                        self.clearance_level = clearance_level

                class MedicalRecord:
                    def __init__(self, patient_name, classification):
                        self.patient_name = patient_name
                        self.classification = classification

                    def can_access(self, user):
                        return self.classification <= user.clearance_level

                # Security classification levels
                class ClearanceLevel:
                    CONFIDENTIAL = 1
                    SECRET = 2
                    TOP_SECRET = 3

                # Example usage
                if __name__ == "__main__":
                    # Create users with different clearance levels
                    doctor = User("Dr. Smith", ClearanceLevel.TOP_SECRET)
                    nurse = User("Nurse Jane", ClearanceLevel.SECRET)
                    receptionist = User("Receptionist Bob", ClearanceLevel.CONFIDENTIAL)

                    # Create medical records with different classifications
                    record1 = MedicalRecord("Patient A", ClearanceLevel.TOP_SECRET)
                    record2 = MedicalRecord("Patient B", ClearanceLevel.SECRET)
                    record3 = MedicalRecord("Patient C", ClearanceLevel.CONFIDENTIAL)

                    # Check access permissions
                    for user in [doctor, nurse, receptionist]:
                        for record in [record1, record2, record3]:
                            if record.can_access(user):
                                print(f"{user.username} can access {record.patient_name} (Classification: {record.classification}).")
                            else:
                                print(f"{user.username} cannot access {record.patient_name} (Classification: {record.classification}).")

            ```
            - output:
            ```
                Dr. Smith can access Patient A (Classification: 3).
                Dr. Smith can access Patient B (Classification: 2).
                Dr. Smith can access Patient C (Classification: 1).
                Nurse Jane cannot access Patient A (Classification: 3).
                Nurse Jane can access Patient B (Classification: 2).
                Nurse Jane can access Patient C (Classification: 1).
                Receptionist Bob cannot access Patient A (Classification: 3).
                Receptionist Bob cannot access Patient B (Classification: 2).
                Receptionist Bob can access Patient C (Classification: 1).

            ```

        4. Role-based access control (RBAC)
        - With role-based access control, named roles are defined to which access privileges are assigned. Users are then assigned to single or multiple roles. RBAC provides enhanced management over other access control models and if properly designed sufficient granularity to provide manageable access control in complex applications. For example, the purchase clerk might be defined as a role with access permissions for a subset of purchase ledger functionality and resources. As employees leave or join an organization then access control management is simplified to defining or revoking membership of the purchases clerk role.

        - RBAC is most effective when there are sufficient roles to properly invoke access controls but not so many as to make the model excessively complex and unwieldy to manage. 

    ### Vertical Access Control.
    - Vertical access controls are mechanisms that restrict access to sensitive functionality to specific types of users.

    - With vertical access controls, different types of users have access to different application functions. For example, an administrator might be able to modify or delete any user's account, while an ordinary user has no access to these actions. Vertical access controls can be more fine-grained implementations of security models designed to enforce business policies such as separation of duties and least privilege.

    - used to restrict access to functions not available for other users in the organization.(admin , regular user)

    ### Horizontal access controls
    - Horizontal access controls are mechanisms that restrict access to resources to specific users.

    - With horizontal access controls, different users have access to a subset of resources of the same type. For example, a banking application will allow a user to view transactions and make payments from their own accounts, but not the accounts of any other user.

    - restrict different users with same level of previllages to access similar resource types

    ### Context-dependent access controls

    - Context-dependent access controls restrict access to functionality and resources based upon the state of the application or the user's interaction with it.

    - Context-dependent access controls prevent a user performing actions in the wrong order. For example, a retail website might prevent users from modifying the contents of their shopping cart after they have made payment.

    ### Exambles:
    - Broken access control vulnerabilities exist when a user can access resources or perform actions that they are not supposed to be able to

        #### Vertical privilege escalation
        - If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation. For example, if a non-administrative user can gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation.

        ### UnProtected Functionality
        -  At its most basic, vertical privilege escalation arises where an application does not enforce any protection for sensitive functionality. For example, administrative functions might be linked from an administrator's welcome page but not from a user's welcome page. However, a user might be able to access the administrative functions by browsing to the relevant admin URL.

        For example, a website might host sensitive functionality at the following URL:
        `https://insecure-website.com/admin`

        This might be accessible by any user, not only administrative users who have a link to the functionality in their user interface. In some cases, the administrative URL might be disclosed in other locations, such as the `robots.txt` file:
       ` https://insecure-website.com/robots.txt`

        Even if the URL isn't disclosed anywhere, an attacker may be able to use a wordlist to brute-force the location of the sensitive functionality.

        - side note : `the robots.txt file is used by websites to prevent search engines such as google to view a particular pages on the search result , so if the website admins don't want this pages urls to be viewed ... they must be interesting`.

        - [Lab 1](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)
        -  In some cases, sensitive functionality is concealed by giving it a less predictable URL. This is an example of so-called "security by obscurity". However, hiding sensitive functionality does not provide effective access control because users might discover the obfuscated URL in a number of ways.

        - Imagine an application that hosts administrative functions at the following URL:
        `https://insecure-website.com/administrator-panel-yb556`
        - This might not be directly guessable by an attacker

        ### Parameter-based access control methods

        - Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:

            A hidden field.
            A cookie.
            A preset query string parameter.

        - The application makes access control decisions based on the submitted value. For example:
        `https://insecure-website.com/login/home.jsp?admin=true`
        `https://insecure-website.com/login/home.jsp?role=1`

        - This approach is insecure because a user can modify the value and access functionality they're not authorized to, such as administrative functions. 

        ### Broken access control resulting from platform misconfiguration

        - Some applications enforce access controls at the platform layer. they do this by restricting access to specific URLs and HTTP methods based on the user's role. For example, an application might configure a rule as follows:
        DENY: POST, /admin/deleteUser, managers

        - This rule denies access to the POST method on the URL /admin/deleteUser, for users in the managers group. Various things can go wrong in this situation, leading to access control bypasses.

        - Some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as X-Original-URL and X-Rewrite-URL. If a website uses rigorous front-end controls to restrict access based on the URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls using a request like the following:
        ```
            POST / HTTP/1.1
            X-Original-URL: /admin/deleteUser
            ...
        ```
        - Purpose of the Header:

            The X-Original-URL header is often used to capture the original URL of the request when a proxy or a load balancer modifies the request before it reaches the application server. It helps in preserving the original request context.

        - How It Works:

            When a client makes a request to the server, the server might redirect or rewrite the URL based on its internal routing rules. In such cases, the server can pass along the original URL through this header.
            For instance, if a user tries to access a resource that requires certain permissions, the server may log or process the request based on the original URL rather than the modified one.

        - If an application relies solely on the URL in the request for access control without validating the headers, it may inadvertently expose sensitive operations to users who shouldn't have access.

        - For example, if the application has strict rules that deny access to /admin/deleteUser for managers but allows an arbitrary header to redefine the URL, a malicious user could craft a request with the X-Original-URL header set to /admin/deleteUser. If the server doesn't check the user's role against the original request URL, the user could gain unauthorized access.

        - Example Scenario

        Consider an application with the following access control rule:

        `DENY: POST, /admin/deleteUser, managers`

        A manager attempts to delete a user via the authorized method, but the request is blocked.
        An attacker, aware of this configuration, sends a request like:
        ```
            POST / HTTP/1.1
            X-Original-URL: /admin/deleteUser
        ```
        - If the application processes the X-Original-URL header without validating the request method or the user's permissions against it, the attacker can bypass the intended access controls.
    
       - [Lab](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

       - An alternative attack relates to the HTTP method used in the request. The front-end controls described in the previous sections restrict access based on the URL and HTTP method. Some websites tolerate different HTTP request methods when performing an action. If an attacker can use the GET (or another) method to perform actions on a restricted URL, they can bypass the access control that is implemented at the platform layer.

        ### IDOR (Insecure-Direct-Object-Reference)
        - Insecure direct object references (IDOR) are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly. The term IDOR was popularized by its appearance in the OWASP 2007 Top Ten. However, it is just one example of many access control implementation mistakes that can lead to access controls being circumvented. IDOR vulnerabilities are most commonly associated with horizontal privilege escalation, but they can also arise in relation to vertical privilege escalation.
            #### IDOR vulnerability with direct reference to database objects
            

        ### Horizontal Privilage Escalation
        - when an attacker gain access to resources beloning to another user of the same privilege level.

        ### multi-step processes
        - when access controls are applied on some of the steps, but ignored on others


    ## Detection
    - how to detect the access controls ?
        ### Black-Box Testing
        - Tester given few information about the system
        - map the application:
            - access all the pages in the application (within your account previlages) , idetify where the web app appears to be interacting with the underlying os
            , make a proxy work in silent to fetch your visited pages

        - understand how access control is implemented for each privilage level
        - manipluate the parameters
        - automate the process (Autorize)

        ### White-Box Testing
        - Teser given lots of information about the system
        - review the code to identify how access control is implemented

        - system defaults to open
        - missing / weak access control checks on functions/resources
        - missing AC rules for POST/PUT/DELETE methods at the API level        

    ## Exploitation
    - how to exploit the AC ?
        - depends on the type of AC
        - just manipulate the vulnerable field / params

