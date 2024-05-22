#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/idr.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/syscalls.h>

#include "phone_book.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dolta Artyom");
MODULE_DESCRIPTION("Phonebook Model");
MODULE_VERSION("0.0");

// static size_t num_users = 0;
static struct idr phonebook;
static char kernelBuffer[BUFFER_SIZE];

found_users_t* get_user_by_surname(const char *surname) {
  found_users_t* found_users = kmalloc(sizeof(found_users_t), GFP_KERNEL);
  user_t* users = kmalloc(sizeof(user_t) * MAX_SAME_NAME_NUMBER, GFP_KERNEL);
  int idx = MAX_USERS;
  int found_num = 0;

  while (idx >= 0) {
    user_t* user = idr_find(&phonebook, idx);
    if (user != NULL && found_num <= MAX_SAME_NAME_NUMBER && strcmp(user->surname, surname) == 0) {
      memcpy(&users[found_num], user, sizeof(user_t));
      ++found_num;
    }
    --idx;
  }
  found_users->found_num = found_num;
  found_users->users = users;
  return found_users;
}

long add_user(user_t* user) {
  user_t *new_user = kmalloc(sizeof(user_t), GFP_KERNEL);
  memcpy(new_user, user, sizeof(user_t));
  idr_alloc(&phonebook, new_user, 0, MAX_USERS, GFP_KERNEL);
  return 0;
}


long delete_user(const char* surname) {
  int idx = MAX_USERS;

  while (idx >= 0) {
    user_t* user = idr_find(&phonebook, idx);
    if (user != NULL && strcmp(user->surname, surname) == 0) {
      kfree(user);
      idr_remove(&phonebook, idx);
      return 0;
    }
    --idx;
  }
  return -1;
}

void parseCommand() {
  user_t user;
  char surname[NAME_SIZE];
  
  if (strncmp(kernelBuffer, "adduser", 7) == 0) {
    sscanf(kernelBuffer + 8, "%s%s%du%s%s",
           user.name, user.surname, &user.age, user.number, user.email);

    if (add_user(&user) == 0) {
      snprintf(kernelBuffer, BUFFER_SIZE, "User added\n\n");
    } else {
      snprintf(kernelBuffer, BUFFER_SIZE,
               "Failed to add user with: \n"
               "Name: %s\n"
               "Surname: %s\n"
               "Age: %du\n"
               "Phone number: %s\n"
               "Email: %s\n\n",
               user.name, user.surname, user.age, user.number, user.email);
    }
  } else if (strncmp(kernelBuffer, "checkuser", 9) == 0) {
    sscanf(kernelBuffer + 10, "%s", surname);
    found_users_t* found_users = get_user_by_surname(surname);
    if (found_users && found_users->users && found_users->found_num > 0) {
      for (int cnt = found_users->found_num; cnt > 0; --cnt) {
        user = found_users->users[cnt - 1];
        snprintf(kernelBuffer, BUFFER_SIZE,
                 "Name: %s\n"
                 "Surname: %s\n"
                 "Age: %du\n"
                 "Phone number: %s\n"
                 "Email: %s\n\n",
                 user.name, user.surname, user.age, user.number, user.email);
      }
    } else {
      snprintf(kernelBuffer, BUFFER_SIZE, "No such user in phonebook\n\n");
    }

    kfree(found_users->users_data);
    kfree(found_users);
  } else if (strncmp(kernelBuffer, "rmuser", 6) == 0) {
    sscanf(kernelBuffer + 7, "%s", surname);
    if (remove_user(surname) == 0) {
      snprintf(kernelBuffer, BUFFER_SIZE, "Removed successfully\n\n");
    } else {
      snprintf(kernelBuffer, BUFFER_SIZE, "Failed to remove\n\n");
    }
  }
}


SYSCALL_DEFINE3(get_user,
                const char*, surname,
                unsigned int, len,
                user_t*, output_data)
{
  char* kernelSurname = kmalloc(sizeof(char) * len, GFP_KERNEL);
  user_t user;

  int err = copy_from_user(kernelSurname, (const char*)surname, sizeof(char) * len);
  if (err) {
    pr_alert("Phonebook syscall_get_user copy_from_user failed with %d\n", err);
    kfree(kernelSurname);
    return err;
  }
  found_users_t* found_users = get_user_by_surname(kernelSurname);
  if (found_users && found_users->users && found_users->found_num > 0) {
    user = found_users->users[found_users->found_num - 1];
  }

  err = copy_to_user((user_t*)output_data, &user, sizeof(user_t));
  if (err) {
    pr_alert("Phonebook syscall_get_user copy_to_user failed with %d\n", err);
    kfree(found_users->users);
    kfree(found_users);
    kfree(kernelSurname);
    return err;
  }

  kfree(found_users->users);
  kfree(found_users);
  kfree(kernelSurname);
  return 0;
}

SYSCALL_DEFINE1(add_user,
                user_t*, intput_data)
{
  user_t kernel_user;
  int err = copy_from_user(&kernel_user, (user_t*)intput_data, sizeof(user_t));
  if (err) {
    pr_alert("Phonebook syscall_add_user copy_from_user failed with %d\n", err);
    return err;
  }

  return add_user(&kernel_user);
}

SYSCALL_DEFINE2(del_user,
                const char*, surname,
                unsigned int, len)
{
  char* kernelSurname = kmalloc(sizeof(char) * len, GFP_KERNEL);

  int err = copy_from_user(kernelSurname, (const char*)surname, sizeof(char) * len);
  if (err) {
    pr_alert("Phonebook syscall_get_user copy_from_user failed with %d\n", err);
    kfree(kernelSurname);
    return err;
  }

  int res = delete_user(kernelSurname);
  kfree(kernelSurname);
  return res;
}

typedef struct {
  struct cdev cdevice;
  struct class *cls;
  int major;
} char_device_t;

static struct char_device_t device;

static int phone_book_open(struct inode *inode, struct file *file);
static int phone_book_release(struct inode *inode, struct file *file);
static ssize_t phone_book_write(struct file *file, const char __user *buf,
                                size_t lbuf, loff_t *ppos);
static ssize_t phone_book_read(struct file *file, char __user *buf, size_t lbuf,
                               loff_t *ppos);

static struct file_operations phonebook_fops = {
    .open = phone_book_open,
    .release = phone_book_release,
    .write = phone_book_write,
    .read = phone_book_read
};

static int phone_book_open(struct inode *inode, struct file *file) {
  pr_info("Opening device %s\n", DEVICE_NAME);
  try_module_get(THIS_MODULE);
  return 0;
}

static int phone_book_release(struct inode *inode, struct file *file) {
  pr_info("Closing device %s\n", DEVICE_NAME);
  module_put(THIS_MODULE);
  return 0;
}

static ssize_t phone_book_write(struct file *file, const char __user *buf,
                                size_t length, loff_t *offset) {
  pr_info("Writing in device %s\n", DEVICE_NAME);
  if (BUFFER_SIZE - *offset < length) {
    length = BUFFER_SIZE - *offset;
  }
  int err = copy_from_user(kernelBuffer + *offset, buf, length);
  if (err) {
    pr_alert("Phonebook device write copy_from_user failed with %d\n", err);
    return err;
  }
  *offset += length;
  kernelBuffer[*offset] = '\0';
  parseCommand();
  return length;
}

static ssize_t phone_book_read(struct file *file, char __user *buf,
                               size_t length, loff_t *offset) {
  pr_info("Read device %s\n\n", DEVICE_NAME);
  size_t data_len = strlen(kernelBuffer);
  if (!*(kernelBuffer + *offset)) {
    *offset = 0;
    return 0;
  }

  if (data_len - *offset < length) {
    length = data_len - *offset;
  }
  int err = copy_to_user(buf, kernelBuffer + *offset, length);
  if (err) {
    pr_alert("Phonebook device read copy_to_user failed with %d\n", err);
    return err;
  }

  *offset += length;
  return length;
}

static int __init add_pb_module() {
  idr_init(&phonebook);
  device.major = MKDEV(222, 0);

  int err = register_chrdev_region(device.major, 1, DEVICE_NAME);
  if (err < 0) {
    pr_alert("Registering chrdev_region failed with %d\n", err);
    return err;
  }

  device.cls = class_create(DEVICE_NAME);
  if (device.cls == NULL) {
    pr_alert("Class_create failed!\n");
    unregister_chrdev_region(device.major, 1);
    return -1;
  }
  device_create(device.cls, NULL, device.major, NULL, DEVICE_NAME);
  pr_info("Device created on /dev/%s\n", DEVICE_NAME);

  cdev_init(&device.cdevice, &phonebook_fops);
  err = cdev_add(&device.cdevice, device.major, 1);
  if (err < 0) {
    pr_alert("Registering char device into system failed with %d\n", err);

    cdev_del(&device.cdevice);
    device_destroy(device.cls, device.major);
    unregister_chrdev_region(device.major, 1);

    return err;
  }

  pr_info("Module PHONEBOOK has been installed\n");
  return 0;
}

static void __exit remove_pb_module(void)
{
  for (size_t idx = MAX_USERS; idx > 0; --idx) {
    idr_remove(&phonebook, idx);
  }

  pr_info("Leaving %s\n", DEVICE_NAME);
  device_destroy(device.cls, device.major);
  cdev_del(&device.cdevice);
  if (device.cls) {
    class_destroy(device.cls);
  }
  unregister_chrdev_region(device.major, 1);

  pr_info("module PHONEBOOK has been uninstalled\n");
}

module_init(add_pb_module)
module_exit(remove_pb_module)