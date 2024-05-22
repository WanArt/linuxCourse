#ifndef PHONE_BOOK_H
#define PHONE_BOOK_H

#define NAME_SIZE 32
#define NUMBER_SIZE 16
#define MAIL_SIZE 32

#define MAX_USERS 1000
#define MAX_SAME_NAME_NUMBER 100

#define DEVICE_NAME "phone_book"

#define BUFFER_SIZE 512

typedef struct {
  char name[NAME_SIZE];
  char surname[NAME_SIZE];
  char number[NUMBER_SIZE];
  char email[MAIL_SIZE];
  int age;
} user_t;

typedef struct {
  user_t* users;
  int found_num;
} found_users_t;

found_users_t* get_user_by_surname(const char* surname);
long add_user(user_t* user);
long delete_user(const char* surname);

#endif