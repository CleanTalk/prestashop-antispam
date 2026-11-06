<?php

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Move order protection off actionValidateOrder.
 * Check off-site payments before the redirect and on-site payments before the order is stored.
 *
 * @param CleantalkAntispam $module
 * @return bool
 */
function upgrade_module_2_1_1($module)
{
    return $module->registerHook('actionDispatcherBefore')
        && $module->registerHook('actionObjectOrderAddBefore')
        && $module->unregisterHook('actionValidateOrder')
        && Configuration::updateValue('CLEANTALKANTISPAM_ORDER_HOOKS_V2', 1);
}
