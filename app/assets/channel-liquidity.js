/* Read-only presentation of the authenticated LND channel snapshot. */
(() => {
  'use strict';
  function render(container, channels) {
    if (!Array.isArray(channels)) throw new Error('Invalid channel snapshot');
    const rows = channels.map(channel => {
      const outgoing = Number(channel.outgoing_sat);
      const incoming = Number(channel.incoming_sat);
      if (![outgoing, incoming].every(value => Number.isSafeInteger(value) && value >= 0)) {
        throw new Error('Invalid channel balance');
      }
      return {id: String(channel.channel_id), outgoing, incoming};
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
    const list = element('div', 'channelLiquidityList');
    for (const row of rows) {
      const total = row.outgoing + row.incoming;
      const outgoingRatio = total ? row.outgoing / total * 100 : 0;
      const incomingRatio = total ? 100 - outgoingRatio : 0;
      const card = element('article', 'channelLiquidityCard');
      card.appendChild(element('h3', 'channelLiquidityName',
        window.__t('liquidity.channel_label', {channel: row.id})));
      card.appendChild(balances(row.outgoing, row.incoming, 'channelLiquidityBalances'));
      const bar = element('div', 'channelLiquidityBar');
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
