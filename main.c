#include "main.h"
#include "sha256.h"

#if defined(GDK_WINDOWING_X11)

  void
  gtk_x11_move_window(
    GtkWidget* window,
    uint32_t x, uint32_t y,
    uint32_t monitor_idx
  ) {
    GdkDisplay* default_display = gdk_display_get_default();
    
    if (GDK_IS_X11_DISPLAY(default_display)) {
      GListModel* monitors = gdk_display_get_monitors(default_display);
      guint n_monitors = g_list_model_get_n_items(monitors);

      if (monitor_idx > n_monitors - 1)
        monitor_idx = n_monitors - 1;

      if (n_monitors == 0)
        return;

      GdkMonitor* chosen_monitor = g_list_model_get_item(monitors, monitor_idx);
      GdkDisplay* monitor_display = gdk_monitor_get_display(chosen_monitor);

      GdkRectangle cm_display_geometry = { 0, 0, 0, 0 };
      gdk_monitor_get_geometry(chosen_monitor, &cm_display_geometry);

      Window xwindow = gdk_x11_surface_get_xid(gtk_native_get_surface(GTK_NATIVE(window)));
      Display* xdisplay = gdk_x11_display_get_xdisplay(monitor_display);

      int32_t StartX = 0;
      int32_t MaxY = cm_display_geometry.height;

      for (size_t idx = 0; idx < monitor_idx; ++idx) {
        GdkMonitor* i_monitor = g_list_model_get_item(monitors, idx);
        GdkRectangle i_display_geometry = { 0, 0, 0, 0 };
        gdk_monitor_get_geometry(i_monitor, &i_display_geometry);

        StartX += i_display_geometry.x;
      }

      if (y > (uint32_t)MaxY)
        y = (uint32_t)MaxY;

      XMoveWindow(xdisplay, xwindow, StartX + x, y);
    }
  }

#endif

#pragma region EXTRAS

  guint8*
  hash_aes256(
    const guint8* data,
    gsize data_len
  ) {
    SHA256_CTX ctx;
    unsigned char hash_buffer[32];

    sha256_init(&ctx);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, hash_buffer);

    return (guint8*)g_base64_encode(hash_buffer, 32);
  }

  gssize
  g_input_stream_readto(
    GInputStream* stream,
    guint8** buffer,
    gboolean include_delim,
    gchar delimiter,
    GError** error
  ) {
    if (stream == NULL || buffer == NULL) {
      if (error != NULL) {
        *error = g_error_new(
          G_IO_ERROR,
          G_IO_ERROR_FAILED,
          "StreamNull"
        );
      }

      return -1;
    }

    if (buffer != NULL) {
      if (*buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
      }
    }

    gssize buffer_sz = 8;
    *buffer = (guint8*)malloc(buffer_sz * sizeof(guint8));

    if (*buffer == NULL)
      return -1;

    guint8 character;
    gssize read_count = 0;
    gssize read_char = 0;

    while ((read_char = g_input_stream_read(
        stream,
        &character,
        1, NULL,
        error
      )) > 0
    ) {
      if ((read_count + 1) == buffer_sz || read_count == buffer_sz) {
        guint8* buffer_realloc = (guint8*)realloc(*buffer, (buffer_sz * 2) * sizeof(guint8));

        if (buffer_realloc == NULL) {
          if (error != NULL) {
            *error = g_error_new(
              G_IO_ERROR,
              G_IO_ERROR_MESSAGE_TOO_LARGE,
              "BufferNull"
            );
          }

          *buffer = NULL;
          
          return -1;
        }

        *buffer = buffer_realloc;
        buffer_sz *= 2;
        
        (*buffer)[buffer_sz - 1] = '\0';
      }

      ++read_count;
      (*buffer)[read_count - 1] = character;

      if (character == delimiter)
        break;
    }

    if (read_char == -1 || read_char == 0) {
      if (*buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
      }
     
      return -1;
    }

    if (include_delim)
      ++read_count;

    if(read_count != buffer_sz) {
      guint8* buffer_realloc = (guint8*)realloc(*buffer, read_count * sizeof(guint8));

      if (buffer_realloc == NULL)
        --read_count;

      if (buffer_realloc != NULL)
        *buffer = buffer_realloc;
    }

    (*buffer)[read_count - 1] = '\0';

    return read_count;
  }
  
  static void
  parse_user_data(void);

  static void
  free_user_data(void);

  static gboolean
  allocate_user(
    const guint8* username,
    const guint8* pwdhash
  ) {
    if (user_data_len == 0)
      user_data = (guint8***)malloc(1 * sizeof(guint8**));
    else
      user_data = (guint8***)realloc(user_data, (user_data_len + 1) * sizeof(guint8**));

    if (user_data == NULL)
      return FALSE;

    user_data[user_data_len] = (guint8**)malloc(2 * sizeof(guint8*));

    if (user_data[user_data_len] == NULL)
      return FALSE;

    user_data[user_data_len][0] = (guint8*)g_strdup((gchar*)username);
    user_data[user_data_len][1] = (guint8*)g_strdup((gchar*)pwdhash);

    ++user_data_len;

    return TRUE;
  }

  static gboolean
  save_user_data(void) {
    GFile* user_data_file = g_file_new_for_path("userdata.csv");
    
    if (!g_file_query_exists(user_data_file, NULL)) {
      GFileOutputStream* cfile = g_file_create(user_data_file, G_FILE_CREATE_NONE, NULL, NULL);
      g_output_stream_close(G_OUTPUT_STREAM(cfile), NULL, NULL);
      g_clear_object(&cfile);

      return FALSE;
    }

    GError* error = NULL;
    GFileIOStream* iofile = g_file_open_readwrite(user_data_file, NULL, &error);
    GOutputStream* ostream = g_io_stream_get_output_stream(G_IO_STREAM(iofile));

    for (gsize idx = 0; idx < user_data_len; ++idx) {
      if (user_data[idx] == NULL)
        continue;

      guint8* username = user_data[idx][0];
      guint8* pwdhash = user_data[idx][1];
    
      guint8* combine = (guint8*)g_strdup_printf("%s,%s\n", username, pwdhash);

      g_output_stream_write(
        ostream,
        combine,
        strlen((gchar*)combine),
        NULL, &error
      );
    }

    g_io_stream_close(G_IO_STREAM(iofile), NULL, NULL);
    g_clear_object(&iofile);

    return TRUE;
  }

  static void
  parse_user_data(void) {
    GFile* user_data_file = g_file_new_for_path("userdata.csv");
    
    if (!g_file_query_exists(user_data_file, NULL)) {
      GFileOutputStream* cfile = g_file_create(user_data_file, G_FILE_CREATE_NONE, NULL, NULL);
      g_output_stream_close(G_OUTPUT_STREAM(cfile), NULL, NULL);
      g_clear_object(&cfile);

      return;
    }

    GError* error = NULL;
    GFileInputStream* ifile = g_file_read(user_data_file, NULL, &error);

    guint8* buffer = NULL;
    gssize read = 0;
    while ((read = g_input_stream_readto(
      G_INPUT_STREAM(ifile),
      &buffer,
      false,
      '\n',
      &error)) > 0
    ) {
      if (read == 1)
        continue;

      guint8* username = NULL;
      guint8* pwdhash = NULL;
      gsize partition_idx = 0;

      for (gsize idx = 0; idx < (gsize)read; ++idx) {
        if (buffer[idx] == ',') {
          partition_idx = idx;
          break;
        }
      }

      if (partition_idx == 0)
        continue;

      username = (guint8*)g_strndup((const gchar*)buffer, partition_idx);

      if (username == NULL) {
        free(buffer);

        g_input_stream_close(G_INPUT_STREAM(ifile), NULL, NULL);
        g_clear_object(&ifile);
        g_clear_object(&user_data_file);
        
        exit(1);
      }

      pwdhash = (guint8*)g_strndup((const gchar*)buffer + partition_idx + 1, read - (partition_idx + 2));

      if (pwdhash == NULL) {
        free(buffer);
        free(username);
        
        g_input_stream_close(G_INPUT_STREAM(ifile), NULL, NULL);
        g_clear_object(&ifile);
        g_clear_object(&user_data_file);
        
        exit(1);
      }

      if (!allocate_user(username, pwdhash)) {
        free(username);
        free(pwdhash);
        free(buffer);

        g_input_stream_close(G_INPUT_STREAM(ifile), NULL, NULL);
        g_clear_object(&ifile);
        g_clear_object(&user_data_file);
        
        exit(1);
      }
    }

    if (error != NULL)
      g_error_free(error);

    g_input_stream_close(G_INPUT_STREAM(ifile), NULL, NULL);
    g_clear_object(&ifile);

    g_clear_object(&user_data_file);
  }

  static gboolean
  check_user_exists(const guint8* username) {
    for (gsize idx = 0; idx < user_data_len; ++idx) {
      if (g_strcmp0((const gchar*)user_data[idx][0], (const gchar*)username) == 0)
        return TRUE;
    }

    return FALSE;
  }

  static gboolean
  check_user_pass_details(
    const guint8* username,
    const guint8* pwdhash
  ) {
    for (gsize idx = 0; idx < user_data_len; ++idx) {
      if (
        g_strcmp0((const gchar*)user_data[idx][0], (const gchar*)username) == 0 &&
        g_strcmp0((const gchar*)user_data[idx][1], (const gchar*)pwdhash) == 0
      ) {
        return TRUE;
      }
    }

    return FALSE;
  }

  static void
  free_user_data(void) {
    if (user_data == NULL)
      return;

    for (gsize idx = 0; idx < user_data_len; ++idx) {
      for (gsize jdx = 0; jdx < 2; ++jdx) {
        free(user_data[idx][jdx]);
        user_data[idx][jdx] = NULL;
      }

      free(user_data[idx]);
      user_data[idx] = NULL;
    }
    
    free(user_data);
    user_data = NULL;
  }

#pragma endregion

#pragma region EVENT_HANDLERS

  static void
  open_page(
    GtkWidget* widget,
    gpointer user_data
  );
  
  static void
  close_page(char* page_name);
  
  static void
  back_clicked(
    GtkWidget* widget,
    gpointer uiser_data
  );

  static void
  open_page(
    GtkWidget* widget,
    gpointer user_data
  ) {
    if (user_data == NULL)
      return;

    char* data = (char*)user_data;

    if (g_strcmp0(data, "signup") == 0) {
      close_page("main");
      gtk_widget_set_visible(box_signup_page, TRUE);
      gtk_window_set_title(GTK_WINDOW(window), "Signup");
    }
    else if (g_strcmp0(data, "login") == 0) {
      close_page("main");
      gtk_widget_set_visible(box_login_page, TRUE);
      gtk_window_set_title(GTK_WINDOW(window), "Login");
    } else if (g_strcmp0(data, "main") == 0) {
      if (gtk_widget_get_visible(box_signup_page))
        close_page("signup");

      if (gtk_widget_get_visible(box_login_page))
        close_page("login");

      gtk_widget_set_visible(box_main_page, TRUE);
      gtk_window_set_title(GTK_WINDOW(window), "Signup and Login");
    }
  }

  static void
  close_page(char* page_name) {
    if (g_strcmp0(page_name, "main") == 0) {
      gtk_widget_set_visible(box_main_page, FALSE);
    } else if (g_strcmp0(page_name, "signup") == 0) {
      gtk_widget_set_visible(box_signup_page, FALSE);
      gtk_editable_delete_text(GTK_EDITABLE(signup_ubox), 0, -1);
      gtk_editable_delete_text(GTK_EDITABLE(signup_pwdbox), 0, -1);
    } else if (g_strcmp0(page_name, "login") == 0) {
      gtk_widget_set_visible(box_login_page, FALSE);
      gtk_editable_delete_text(GTK_EDITABLE(login_ubox), 0, -1);
      gtk_editable_delete_text(GTK_EDITABLE(login_pwdbox), 0, -1);
    }
  }

  static void
  back_clicked(
    GtkWidget* widget,
    gpointer user_data
  ) {
    if (user_data == NULL)
      return;

    if (g_strcmp0(user_data, "from_signup") == 0) {
      close_page("signup");
      open_page(widget, "main");
    } else if (g_strcmp0(user_data, "from_login") == 0) {
      close_page("login");
      open_page(widget, "main");
    }
  }

  static void
  reset_signup_btn(void) {
    gtk_button_set_label(GTK_BUTTON(signup_confirm), "Signup");
  }

  static void
  signup_clicked(
    GtkWidget* widget,
    gpointer user_data
  ) {
    const guint8* username = (const guint8*)gtk_editable_get_text(GTK_EDITABLE(signup_ubox));

    if (strlen((gchar*)username) == 0) {
      gtk_button_set_label(GTK_BUTTON(signup_confirm), "Empty Username");

      g_timeout_add(750, G_SOURCE_FUNC(reset_signup_btn), NULL);
     
      return;
    }

    if (check_user_exists(username)) {
      gtk_button_set_label(GTK_BUTTON(signup_confirm), "User Exists");

      g_timeout_add(750, G_SOURCE_FUNC(reset_signup_btn), NULL);

      return;
    }

    const guint8* pwd = (const guint8*)gtk_editable_get_text(GTK_EDITABLE(signup_pwdbox));

    if (strlen((gchar*)pwd) == 0) {
      gtk_button_set_label(GTK_BUTTON(signup_confirm), "Empty Password");

      g_timeout_add(750, G_SOURCE_FUNC(reset_signup_btn), NULL);
     
      return;
    }

    const guint8* pwdhash = hash_aes256(pwd, strlen((gchar*)pwd));
    pwd = NULL;

    if (!allocate_user(username, pwdhash)) {
      g_print("Failed to Allocate User: %s\n", username);
      
      gtk_button_set_label(GTK_BUTTON(signup_confirm), "malloc(...) FAILED");
     
      g_timeout_add(750, G_SOURCE_FUNC(reset_signup_btn), NULL);
    } else {
      save_user_data();

      gtk_button_set_label(GTK_BUTTON(signup_confirm), "Registered");
     
      g_timeout_add(750, G_SOURCE_FUNC(reset_signup_btn), NULL);
    }
  }

  static void
  reset_login_btn(void) {
    gtk_button_set_label(GTK_BUTTON(login_confirm), "Login");
  }

  static void
  login_clicked(
    GtkWidget* widget,
    gpointer user_data
  ) {
    const guint8* username = (const guint8*)gtk_editable_get_text(GTK_EDITABLE(login_ubox));
    const guint8* pwd = (const guint8*)gtk_editable_get_text(GTK_EDITABLE(login_pwdbox));

    if (strlen((gchar*)username) == 0 || strlen((gchar*)pwd) == 0) {
      gtk_button_set_label(GTK_BUTTON(login_confirm), "Empty Field(s)");

      g_timeout_add(750, G_SOURCE_FUNC(reset_login_btn), NULL);
     
      return;
    }

    const guint8* pwdhash = hash_aes256(pwd, strlen((gchar*)pwd));
    pwd = NULL;

    if (check_user_pass_details(username, pwdhash)) {
      gtk_button_set_label(GTK_BUTTON(login_confirm), "Login Successful");

      g_timeout_add(500, G_SOURCE_FUNC(g_application_quit), G_APPLICATION(app));
    }
    else {
      g_print("failed\n");
      gtk_button_set_label(GTK_BUTTON(login_confirm), "Invalid Credentials");
    
      g_timeout_add(1000, G_SOURCE_FUNC(reset_login_btn), NULL);
    }
  }

#pragma endregion

#pragma region STARTUP_EVENT_HANDLERS

  static void
  startup(
    GtkApplication* app,
    gpointer user_data
  ) {
    css_provider = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css_provider, "app.css");

    if (css_provider == NULL)
      return;

    gtk_style_context_add_provider_for_display(
      gdk_display_get_default(),
      GTK_STYLE_PROVIDER(css_provider),
      GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );
  }

  static void
  gen_main_page(void) {
    box_main_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);

    signup_btn = gtk_button_new_with_label("Signup");
    gtk_widget_set_name(signup_btn, "signup-btn");
    g_signal_connect(signup_btn, "clicked", G_CALLBACK(open_page), "signup");

    login_btn = gtk_button_new_with_label("Login");
    gtk_widget_set_name(login_btn, "login-btn");
    g_signal_connect(login_btn, "clicked", G_CALLBACK(open_page), "login");

    gtk_box_append(GTK_BOX(box_main_page), signup_btn);
    gtk_box_append(GTK_BOX(box_main_page), login_btn);

    gtk_box_append(GTK_BOX(main_container), box_main_page);
  }

  static void
  gen_signup_page(void) {
    box_signup_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);

    /* CREATES USERNAME INPUT GROUP */
      signup_ulabel = gtk_label_new("Username");
      gtk_widget_set_name(signup_ulabel, "signup-ulabel");
      signup_ubox = gtk_entry_new();
    
    /* CREATES PASSWORD INPUT GROUP */
      signup_pwdlabel = gtk_label_new("Password");
      gtk_widget_set_name(signup_pwdlabel, "signup-pwdlabel");
      signup_pwdbox = gtk_password_entry_new();

    /* CREATES "SIGNUP" AND "BACK" GROUP */
      box_signup_btns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
      gtk_widget_set_name(box_signup_btns, "box-signup-btns");

      signup_confirm = gtk_button_new_with_label("Signup");
      g_signal_connect(signup_confirm, "clicked", G_CALLBACK(signup_clicked), NULL);
      signup_back = gtk_button_new_with_label("Back");
      g_signal_connect(signup_back, "clicked", G_CALLBACK(back_clicked), "from_signup");

      gtk_box_set_homogeneous(GTK_BOX(box_signup_btns), TRUE);
    
    /* APPENDS "SIGNUP" AND "BACK" TO BOX_SIGNUP_BTNS */
      gtk_box_append(GTK_BOX(box_signup_btns), signup_confirm);
      gtk_box_append(GTK_BOX(box_signup_btns), signup_back);

    /* APPENDS ALL WIDGETS TO BOX_SIGNUP_PAGE */
      gtk_box_append(GTK_BOX(box_signup_page), signup_ulabel);
      gtk_box_append(GTK_BOX(box_signup_page), signup_ubox);
      gtk_box_append(GTK_BOX(box_signup_page), signup_pwdlabel);
      gtk_box_append(GTK_BOX(box_signup_page), signup_pwdbox);
      gtk_box_append(GTK_BOX(box_signup_page), box_signup_btns);
    
    /* APPENDS PAGE TO MAIN_CONTAINER AND MAKES INVISIBLE */
      gtk_box_append(GTK_BOX(main_container), box_signup_page);
      gtk_widget_set_visible(box_signup_page, FALSE);
  }

  static void
  gen_login_page(void) {
    box_login_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);

    /* CREATES USERNAME INPUT GROUP */
      login_ulabel = gtk_label_new("Username");
      gtk_widget_set_name(login_ulabel, "login-ulabel");
      login_ubox = gtk_entry_new();

    /* CREATES PASSWORD INPUT GROUP */
      login_pwdlabel = gtk_label_new("Password");
      gtk_widget_set_name(login_pwdlabel, "login-pwdlabel");
      login_pwdbox = gtk_password_entry_new();

    /* CREATES "LOGIN" AND "BACK" GROUP */
      box_login_btns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
      gtk_widget_set_name(box_login_btns, "box-login-btns");

      login_confirm = gtk_button_new_with_label("Login");
      g_signal_connect(login_confirm, "clicked", G_CALLBACK(login_clicked), NULL);
      login_back = gtk_button_new_with_label("Back");
      g_signal_connect(login_back, "clicked", G_CALLBACK(back_clicked), "from_login");

      gtk_box_set_homogeneous(GTK_BOX(box_login_btns), TRUE);

    /* APPENDS "SIGNUP" AND "BACK" TO BOX_SIGNUP_BTNS */
      gtk_box_append(GTK_BOX(box_login_btns), login_confirm);
      gtk_box_append(GTK_BOX(box_login_btns), login_back);

    /* APPENDS ALL WIDGETS TO BOX_LOGIN_PAGE */
      gtk_box_append(GTK_BOX(box_login_page), login_ulabel);
      gtk_box_append(GTK_BOX(box_login_page), login_ubox);
      gtk_box_append(GTK_BOX(box_login_page), login_pwdlabel);
      gtk_box_append(GTK_BOX(box_login_page), login_pwdbox);
      gtk_box_append(GTK_BOX(box_login_page), box_login_btns);

    /* APPENDS PAGE TO MAIN_CONTAINER AND MAKES INVISIBLE */
      gtk_box_append(GTK_BOX(main_container), box_login_page);
      gtk_widget_set_visible(box_login_page, FALSE);
  }

  static void
  activate(
    GtkApplication* app,
    gpointer user_data
  ) {
    window = gtk_application_window_new(app);

    main_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 25);
    gtk_widget_set_name(main_container, "main-container");

    gen_main_page();
    gen_signup_page();
    gen_login_page();

    watermark = gtk_label_new("Programmed by Sigma");
    gtk_widget_set_name(watermark, "watermark");

    gtk_box_append(GTK_BOX(main_container), watermark);

    gtk_window_set_default_size(GTK_WINDOW(window), 500, 0);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
    gtk_window_set_title(GTK_WINDOW(window), "Signup and Login");
    gtk_window_set_child(GTK_WINDOW(window), main_container);
    gtk_window_present(GTK_WINDOW(window));

    #if defined(GDK_WINDOWING_X11)
      gtk_x11_move_window(window, 50, (1080 / 2) - (300 / 2), 1);
    #endif
  }

#pragma endregion

int32_t main(
  int32_t argc,
  char** argv
) {
  parse_user_data();

  app = gtk_application_new(
    "com.github.sigmaeg.signupandlogin",
    G_APPLICATION_DEFAULT_FLAGS
  );

  g_signal_connect(app, "startup", G_CALLBACK(startup), NULL);
  g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

  int32_t status = g_application_run(G_APPLICATION(app), argc, argv);
  g_clear_object(&app);

  save_user_data();

  free_user_data();
}
