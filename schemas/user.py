def userEntity(user) -> dict:
    return {
        "id": str(user["id"]),
        "name": user.get("name", "N/A"),
        "email": user.get("email", "N/A"),
        "mobile_number": user.get("mobile_number", "N/A"),
        "location": user.get("location", "N/A"),
        "role": user.get("role", "N/A")
    }

def usersEntity(users) -> list:
    return [userEntity(user) for user in users]
