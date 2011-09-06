<?php

/**
 * Admin settings from for weibo
 */
function tencent_weibo_admin_form() {
  $form['tencent_weibo_api_key'] = array(
    '#type' => 'textfield',
    '#title' => t('App Key'),
    '#default_value' => variable_get('tencent_weibo_api_key', '')
  );
  $form['tencent_weibo_api_secret'] = array(
    '#type' => 'textfield',
    '#title' => t('App Secret'),
    '#default_value' => variable_get('tencent_weibo_api_secret', '')
  );
  return system_settings_form($form);
}
