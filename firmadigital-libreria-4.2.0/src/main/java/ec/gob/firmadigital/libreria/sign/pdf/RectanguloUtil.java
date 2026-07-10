/*
 * Copyright (C) 2020 
 * Authors: Ricardo Arguello, Misael Fernández
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.*
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package ec.gob.firmadigital.libreria.sign.pdf;

import com.itextpdf.kernel.geom.Rectangle;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RectanguloUtil {

    public static final String POSITION_ON_PAGE_LOWER_LEFT_X = "PositionOnPageLowerLeftX";
    public static final String POSITION_ON_PAGE_LOWER_LEFT_Y = "PositionOnPageLowerLeftY";
    public static final String POSITION_ON_PAGE_UPPER_RIGHT_X = "PositionOnPageUpperRightX";
    public static final String POSITION_ON_PAGE_UPPER_RIGHT_Y = "PositionOnPageUpperRightY";

    private static final Logger LOGGER = Logger.getLogger(RectanguloUtil.class.getName());

    public static Rectangle getPositionOnPage(Properties extraParams) {
        if (extraParams == null) {
            LOGGER.severe("Se ha pedido una posicion para un elemento grafico nulo");
            return null;
        }

        if (extraParams.getProperty(POSITION_ON_PAGE_LOWER_LEFT_X) != null
                && extraParams.getProperty(POSITION_ON_PAGE_LOWER_LEFT_Y) != null
                && extraParams.getProperty(POSITION_ON_PAGE_UPPER_RIGHT_X) != null
                && extraParams.getProperty(POSITION_ON_PAGE_UPPER_RIGHT_Y) != null) {
            try {
                int llx = Integer.parseInt(extraParams.getProperty(POSITION_ON_PAGE_LOWER_LEFT_X).trim());
                int lly = Integer.parseInt(extraParams.getProperty(POSITION_ON_PAGE_LOWER_LEFT_Y).trim());
                int urx = Integer.parseInt(extraParams.getProperty(POSITION_ON_PAGE_UPPER_RIGHT_X).trim());
                int ury = Integer.parseInt(extraParams.getProperty(POSITION_ON_PAGE_UPPER_RIGHT_Y).trim());

                int width = urx - llx;
                int height = ury - lly;

                if (width <= 0 || height <= 0) {
                    LOGGER.log(Level.SEVERE, "Se ha indicado una posicion invalida para la firma: ancho/alto no positivos. Valores: ({0}, {1}), ({2}, {3})", new Object[]{llx, lly, urx, ury});
                    return null;
                }

                return new Rectangle(llx, lly, width, height);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.SEVERE, "Se ha indicado una posicion invalida para la firma: {0}", e);
            }
        }

        return null;
    }
}
