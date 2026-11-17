/* Read-only presentation of the authenticated LND channel snapshot. */
(() => {
  'use strict';
  function render(container, channels, localAlias) {
    if (!Array.isArray(channels)) throw new Error('Invalid channel snapshot');
    const rows = channels.map(channel => {
      const outgoing = Number(channel.outgoing_sat);
      const incoming = Number(channel.incoming_sat);
      if (![outgoing, incoming].every(value => Number.isSafeInteger(value) && value >= 0)) {
        throw new Error('Invalid channel balance');
      }
      return {
        id: String(channel.channel_id),
        outgoing, incoming, capacity: channel.capacity_sat,
        alias: typeof channel.peer_alias === 'string' ? channel.peer_alias.trim() : '',
        pubkey: channel.remote_pubkey || '',
      };
    });
    const format = value => new Intl.NumberFormat(window.getLang()).format(value);
    function element(tag, className, text) {
      const node = document.createElement(tag);
      node.className = className;
      if (text !== undefined) node.textContent = text;
      return node;
    }
    function balances(outgoing, incoming, className) {
      const group = element('div', className);
      for (const [side, value, label] of [
        ['outgoing', outgoing, window.__t('liquidity.outgoing')],
        ['incoming', incoming, window.__t('liquidity.incoming')],
      ]) {
        const metric = element('div', 'channelLiquidityMetric ' + side);
        metric.appendChild(element('span', 'channelLiquidityLabel', label));
        metric.appendChild(element('strong', 'channelLiquidityAmount', format(value) + ' sats'));
        group.appendChild(metric);
      }
      return group;
    }
    // Build detached so malformed data cannot leave a partial, misleading view.
    const overview = element('div', 'channelLiquidityOverview');
    overview.appendChild(element('p', 'channelLiquidityCount',
      window.__t('liquidity.active_channels', {count: format(rows.length)})));
    if (!rows.length) {
      overview.appendChild(element('p', 'channelLiquidityEmpty', window.__t('liquidity.empty')));
      container.replaceChildren(overview);
      return;
    }
    overview.appendChild(balances(
      rows.reduce((sum, row) => sum + row.outgoing, 0),
      rows.reduce((sum, row) => sum + row.incoming, 0),
      'channelLiquidityTotals',
    ));
    if (typeof localAlias === 'string' && localAlias.trim()) {
      const label = overview.querySelector('.channelLiquidityTotals .outgoing .channelLiquidityLabel');
      label.textContent = localAlias.trim() + ' · ' + label.textContent;
    }
    const largestBalance = rows.reduce((largest, row) => Math.max(largest, row.outgoing + row.incoming), 0);
    const list = element('div', 'channelLiquidityList');
    for (const row of rows) {
      const total = row.outgoing + row.incoming;
      const outgoingRatio = total ? row.outgoing / total * 100 : 0;
      const incomingRatio = total ? 100 - outgoingRatio : 0;
      const card = element('article', 'channelLiquidityCard');
      const channelLabel = window.__t('liquidity.channel_label', {channel: row.id});
      const heading = element('h3', 'channelLiquidityName', row.alias || row.pubkey || channelLabel);
      heading.title = channelLabel;
      if (row.alias && row.pubkey) heading.appendChild(element('small', 'channelLiquidityLabel', row.pubkey));
      card.appendChild(heading);
      if (Number.isSafeInteger(row.capacity) && row.capacity > 0) {
        card.appendChild(element('p', 'channelLiquidityName',
          window.__t('liquidity.capacity', {amount: format(row.capacity)})));
      }
      card.appendChild(balances(row.outgoing, row.incoming, 'channelLiquidityBalances'));
      const bar = element('div', 'channelLiquidityBar');
      bar.style.width = (largestBalance ? total / largestBalance * 100 : 0) + '%';
      bar.setAttribute('role', 'img');
      bar.setAttribute('aria-label', window.__t('liquidity.distribution', {
        outgoing: format(row.outgoing), incoming: format(row.incoming),
        outgoingPercent: format(Math.round(outgoingRatio)),
        incomingPercent: format(Math.round(incomingRatio)),
      }));
      for (const [side, ratio] of [['outgoing', outgoingRatio], ['incoming', incomingRatio]]) {
        const segment = element('span', 'channelLiquiditySegment ' + side);
        segment.style.width = ratio + '%';
        segment.setAttribute('aria-hidden', 'true');
        bar.appendChild(segment);
      }
      card.appendChild(bar);
      const percentages = element('div', 'channelLiquidityPercentages');
      percentages.setAttribute('aria-hidden', 'true');
      percentages.appendChild(element('span', '', format(Math.round(outgoingRatio)) + '%'));
      percentages.appendChild(element('span', '', format(Math.round(incomingRatio)) + '%'));
      card.appendChild(percentages);
      list.appendChild(card);
    }
    overview.appendChild(list);
    container.replaceChildren(overview);
  }
  window.Bolt12ChannelLiquidity = {render};
})();
