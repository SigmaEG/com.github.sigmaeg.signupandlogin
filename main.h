#pragma once

#ifndef _CGSSL_MAIN_H
#define _CGSSL_MAIN_H

#include <gtk/gtk.h>
#include <stdbool.h>

#if defined(_WIN32)
  
  #include <windows.h>    

#endif

#if defined(GDK_WINDOWING_X11)

  #include <gdk/x11/gdkx.h>

  void
  gtk_x11_move_window(
    GtkWidget* window,
    uint32_t x, uint32_t y,
    uint32_t monitor_idx
  );

#endif

#pragma region GLOBAL_DEFINITIONS

  guint8*** user_data = NULL;
  gsize user_data_len = 0;

#pragma endregion

#pragma region GLOBAL_WIDGETS

  GtkApplication* app = NULL;
  GtkCssProvider* css_provider = NULL;
  GtkWidget* window = NULL;
  GtkWidget* main_container = NULL;
  GtkWidget* watermark = NULL;

#pragma endregion

#pragma region MAIN_PAGE_WIDGETS

  GtkWidget* box_main_page = NULL;
  GtkWidget* signup_btn = NULL;
  GtkWidget* login_btn = NULL;

#pragma endregion

#pragma region SIGNUP_PAGE_WIDGETS

  GtkWidget* box_signup_page = NULL;

  GtkWidget* signup_ulabel = NULL;
  GtkWidget* signup_ubox = NULL;

  GtkWidget* signup_pwdlabel = NULL;
  GtkWidget* signup_pwdbox = NULL;

  GtkWidget* box_signup_btns = NULL;
  GtkWidget* signup_confirm = NULL;
  GtkWidget* signup_back = NULL;

#pragma endregion

#pragma region LOGIN_PAGE_WIDGETS

  GtkWidget* box_login_page = NULL;

  GtkWidget* login_ulabel = NULL;
  GtkWidget* login_ubox = NULL;

  GtkWidget* login_pwdlabel = NULL;
  GtkWidget* login_pwdbox = NULL;

  GtkWidget* box_login_btns = NULL;
  GtkWidget* login_confirm = NULL;
  GtkWidget* login_back = NULL;

#pragma endregion

#pragma region EXTRAS

  guint8*
  hash_aes256(
    const guint8* data,
    gsize data_len
  );

  gssize
  g_input_stream_readto(
    GInputStream* stream,
    guint8** buffer,
    gboolean include_delim,
    gchar delimiter,
    GError** error
  );

#pragma endregion

#endif
