<?php

/**
 * Callback function that will be returned by tencent
 */
function tencent_weibo_callback() {
  module_load_include('php', 'tencent_weibo', 'tencent_weibo.lib');
  $o = new MBOpenTOAuth(variable_get('tencent_weibo_api_key', '') , variable_get('tencent_weibo_api_secret', '') , $_SESSION['tencent_weibo_keys']['oauth_token'] , $_SESSION['tencent_weibo_keys']['oauth_token_secret']);
  unset($_SESSION['tencent_weibo_keys']);
  $last_key = $o->getAccessToken($_REQUEST['oauth_verifier']);
  if(count($last_key) ==1) {
    $last_key = array_values(array_flip($last_key));
    watchdog('weibo_tencent', $last_key['0']);
    drupal_set_message(t('Internal error, please contact site administrator.'), 'error');
    return '';
  }
  $c = new MBApiClient(variable_get('tencent_weibo_api_key', '') , variable_get('tencent_weibo_api_secret', ''), $last_key['oauth_token'] , $last_key['oauth_token_secret']);
  $me = $c->getUserInfo();
  if($me['errcode'] !== 0) {
    watchdog('weibo_tencent', $me['msg'], $me);
    drupal_set_message(t('Internal error, please contact site administrator.'), 'error');
    return '1';
  }

  $uid = db_result(db_query('SELECT uid FROM {weibo_tencent_users} WHERE tencent_name="%s"', $me['data']['name']));
  // User is already registered
  if($uid) {
    $account = user_load($uid);
    user_external_login($account);
    db_query('UPDATE {weibo_tencent_users} SET oauth_token="%s", oauth_token_secret="%s" WHERE uid=%d', $last_key['oauth_token'], $last_key['oauth_token_secret'], $account->uid);
    drupal_goto();
  }
  // User is not registered. Register new user
  else {
    $_SESSION['tencent_weibo_token'] = $last_key + array('name' => $me['data']['name']);
    drupal_goto('user/register/tencent-weibo');
  }
}

function tencent_weibo_register_submit($form, $form_state) {
  db_query('INSERT INTO {weibo_tencent_users} SET uid=%d, tencent_name="%s", oauth_token="%s", oauth_token_secret="%s"', $form_state['user']->uid, $_SESSION['tencent_weibo_token']['name'], $_SESSION['tencent_weibo_token']['oauth_token'], $_SESSION['tencent_weibo_token']['oauth_token_secret']);
  unset($_SESSION['tencent_weibo_token']);
  user_external_login($form_state['user']);
  drupal_goto('user/' . $form_state['user']->uid . '/edit');
}

/**
 * Redirect the user to the tencent login page
 */
function tencent_weibo_login() {
  module_load_include('php', 'tencent_weibo', 'tencent_weibo.lib');
  $o = new MBOpenTOAuth(variable_get('tencent_weibo_api_key', '') , variable_get('tencent_weibo_api_secret', ''));
  $keys = $o->getRequestToken(url('tencent-weibo/callback', array('absolute' => TRUE)));//这里填上你的回调URL
  $tencent_url = $o->getAuthorizeURL( $keys['oauth_token'] ,false,'');
  $_SESSION['tencent_weibo_keys'] = $keys;
  drupal_goto($tencent_url);
}